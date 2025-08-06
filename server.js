const express = require('express')
const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))

app.use((req, res, next) => {
    res.locals.error = []
    next()
})

app.get('/', (req, res) =>{
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})


app.post("/login", (req, res) => {
    const errors = [];

    let { username, password } = req.body;

    username = typeof username === "string" ? username.trim() : "";
    password = typeof password === "string" ? password : "";

    console.log("Received username:", username);
    console.log("Received password:", password);

    // Username validations
    if (username.length < 3) {
        errors.push("Username must be at least 3 characters long");
    }
    if (username.length > 10) {
        errors.push("Username must be at most 10 characters long");
    }
    if (!/^[a-zA-Z0-9]+$/.test(username)) {
        errors.push("Username must not contain special characters");
    }

    // Password validations
    if (password.length < 8) {
        errors.push("Password must be at least 8 characters long");
    }
    if (password.length > 20) {
        errors.push("Password must be at most 20 characters long");
    }
    if (
      !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/
        .test(password)
    ) {
        errors.push("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");
    }

    console.log("Validation Errors:", errors);

    if (errors.length > 0) {
        return res.render("login", { error: errors, username });
    }

    res.send("Thank you for registering!");
});

app.post("/register", (req, res) => {
    const errors = [];

    let { username, password } = req.body;

    username = typeof username === "string" ? username.trim() : "";
    password = typeof password === "string" ? password : "";

    if (username.length < 3)
        errors.push("Username must be at least 3 characters long");

    if (username.length > 10)
        errors.push("Username must be at most 10 characters long");

    if (!/^[a-zA-Z0-9]+$/.test(username))
        errors.push("Username must not contain special characters");

    if (password.length < 8)
        errors.push("Password must be at least 8 characters long");

    if (password.length > 20)
        errors.push("Password must be at most 20 characters long");

    if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/.test(password))
        errors.push("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");

    if (errors.length > 0) {
        return res.render("homepage", { error: errors });
    }

    res.send("Thank you for registering!");
});

app.listen(3000)