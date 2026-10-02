const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 5000;
const SECRET = "taskflow_secret_2026";

app.use(cors());
app.use(express.json());

const dataDir = path.join(__dirname, "data");
const dataFile = path.join(dataDir, "database.json");

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

if (!fs.existsSync(dataFile)) {
  fs.writeFileSync(
    dataFile,
    JSON.stringify({ users: [], tasks: [] }, null, 2)
  );
}

const readDB = () =>
  JSON.parse(fs.readFileSync(dataFile, "utf8"));

const saveDB = (db) =>
  fs.writeFileSync(dataFile, JSON.stringify(db, null, 2));

function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "Login required" });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}

/* HOME */
app.get("/", (req, res) => {
  res.json({
    message: "TaskFlow API is running",
    status: "online"
  });
});

/* REGISTER */
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      message: "All fields are required"
    });
  }

  const db = readDB();

  if (db.users.some(u => u.email === email.toLowerCase())) {
    return res.status(409).json({
      message: "Email already registered"
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = {
    id: Date.now(),
    name,
    email: email.toLowerCase(),
    password: hashedPassword,
    role: "user"
  };

  db.users.push(user);
  saveDB(db);

  const token = jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    },
    SECRET,
    { expiresIn: "7d" }
  );

  res.status(201).json({
    message: "Account created successfully",
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
});

/* LOGIN */
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const db = readDB();

  const user = db.users.find(
    u => u.email === email?.toLowerCase()
  );

  if (!user) {
    return res.status(401).json({
      message: "Invalid email or password"
    });
  }

  const valid = await bcrypt.compare(
    password,
    user.password
  );

  if (!valid) {
    return res.status(401).json({
      message: "Invalid email or password"
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    },
    SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    message: "Login successful",
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
});

/* GET TASKS */
app.get("/api/tasks", auth, (req, res) => {
  const db = readDB();

  const tasks = db.tasks.filter(
    task => task.userId === req.user.id
  );

  res.json(tasks);
});

/* CREATE TASK */
app.post("/api/tasks", auth, (req, res) => {
  const {
    title,
    description,
    priority,
    status,
    dueDate
  } = req.body;

  if (!title || !description || !dueDate) {
    return res.status(400).json({
      message: "Title, description and due date are required"
    });
  }

  const db = readDB();

  const task = {
    id: Date.now(),
    userId: req.user.id,
    title,
    description,
    priority: priority || "Medium",
    status: status || "Pending",
    dueDate,
    createdAt: new Date().toISOString()
  };

  db.tasks.push(task);
  saveDB(db);

  res.status(201).json({
    message: "Task created successfully",
    task
  });
});

/* UPDATE TASK */
app.put("/api/tasks/:id", auth, (req, res) => {
  const db = readDB();
  const id = Number(req.params.id);

  const index = db.tasks.findIndex(
    task =>
      task.id === id &&
      task.userId === req.user.id
  );

  if (index === -1) {
    return res.status(404).json({
      message: "Task not found"
    });
  }

  db.tasks[index] = {
    ...db.tasks[index],
    ...req.body,
    id,
    userId: req.user.id,
    updatedAt: new Date().toISOString()
  };

  saveDB(db);

  res.json({
    message: "Task updated successfully",
    task: db.tasks[index]
  });
});

/* DELETE TASK */
app.delete("/api/tasks/:id", auth, (req, res) => {
  const db = readDB();
  const id = Number(req.params.id);

  const exists = db.tasks.some(
    task =>
      task.id === id &&
      task.userId === req.user.id
  );

  if (!exists) {
    return res.status(404).json({
      message: "Task not found"
    });
  }

  db.tasks = db.tasks.filter(
    task =>
      !(
        task.id === id &&
        task.userId === req.user.id
      )
  );

  saveDB(db);

  res.json({
    message: "Task deleted successfully"
  });
});

app.listen(PORT, () => {
  console.log(`TaskFlow API running on http://localhost:${PORT}`);
});