const express = require("express");
const app = express();

// API-ABUSE-001: Missing authentication check - routes without auth middleware
app.get("/profile", (req, res) => {
    res.json({ user: "data" });
});

app.post("/settings", (req, res) => {
    res.json({ ok: true });
});

// API-ABUSE-002: BOLA - user ID from request params used directly in DB query
app.get("/users/:id", async (req, res) => {
    const userId = req.params.userId;
    const user = await User.findById(req.params.id);
    res.json(user);
});

app.delete("/users/:id", async (req, res) => {
    await User.deleteOne(req.params.id);
    res.json({ deleted: true });
});

// API-ABUSE-003: Missing rate limiting on auth endpoints
app.post("/login", (req, res) => {
    res.json({ token: "abc" });
});

app.post("/auth/register", (req, res) => {
    res.json({ ok: true });
});

app.post("/password/reset", (req, res) => {
    res.json({ ok: true });
});

// API-ABUSE-004: Mass assignment - full request body bound to model
app.post("/users", async (req, res) => {
    const user = new User(req.body);
    await user.save();
    res.json(user);
});

app.put("/users/:id", async (req, res) => {
    Object.assign(existingUser, req.body);
    await User.update(req.body);
    res.json({ ok: true });
});

// API-ABUSE-005: Verbose error responses
app.get("/data", async (req, res) => {
    try {
        const data = await fetchData();
        res.json(data);
    } catch (err) {
        res.status(500).json({ message: err.message, stack: err.stack });
        res.send({ error: error.message });
    }
});
