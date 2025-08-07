require('dotenv').config()
const jwt = require('jsonwebtoken')
const sanitizeHtml = require('sanitize-html')
const express = require('express')
const cookieParser = require('cookie-parser')
const bcrypt = require('bcrypt')
const db = require('better-sqlite3')("ourApp.db")
db.pragma("journal_mode = WAL")

// Database setup
const  createTables = db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
`)
createTables.run()

const createPostsTable = db.prepare(`
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        userId INTEGER NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id)
    )
`)
createPostsTable.run()
// Database setup ends here

const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({ extended: false }))
app.use(express.static("public"))
app.use(cookieParser())

app.use((req, res, next) => {
    res.locals.error = []

    // try to catch incoming cookie
    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    }catch(err) {
        req.user = false
    }
    res.locals.user = req.user
    console.log(req.user)
    next()
})

function posts(req, res, next) {
    const postsStatement = db.prepare(`SELECT * FROM posts WHERE userId = ?`)
    const posts = postsStatement.all(req.user.userid)
    res.render("dashboard", { posts })
}


function mustBeLoggedIn(req, res, next) {
    if (!req.user) {
        return res.redirect("/")
    }
    next()
}

app.get('/', (req, res) =>{
    if (req.user) {
        const postsStatement = db.prepare(`SELECT * FROM posts WHERE userId = ?`)
        const posts = postsStatement.all(req.user.userid)
        return res.render("dashboard", { posts })
    }
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/logout", (req, res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.get("/create-post", mustBeLoggedIn, (req, res) => {
    res.render("create-post")
})

function sharedPostValidation(data) {
    const errors = [];
    if (typeof data.title !== "string" || data.title.trim().length === 0) {
        errors.push("Title is required");
    }
    if (typeof data.content !== "string" || data.content.trim().length === 0) {
        errors.push("Content is required");
    }
    data.title = sanitizeHtml(data.title, {allowedTags: [], allowedAttributes: {}})
    data.content = sanitizeHtml(data.content, {allowedTags: [], allowedAttributes: {}})

    if (!data.title) errors.push("Title is required")
    if (!data.content) errors.push("Content is required")
    return errors;
}

app.get("/post/:id", (req, res) => {
    const statement = db.prepare(`SELECT post.*, users.username FROM posts INNER JOIN users ON posts.userId = users.id WHERE posts.id = ?`)
    const post = statement.get(req.params.id);    
    if (!post) {
        return res.redirect("/")
    }
    res.render("single-post", { post })
})

app.post("/create-post", mustBeLoggedIn, (req, res) => {
    const errors = sharedPostValidation(req.body);
    if (errors.length > 0) {
        return res.render("create-post", { error: errors, title: req.body.title, content: req.body.content, author: req.user.username });
    }    

    // insert the post into the database
    const insertPost = db.prepare(`INSERT INTO posts (title, content, author, userId) VALUES (?, ?, ?, ?)`)
    const result = insertPost.run(req.body.title, req.body.content, req.user.username, req.user.userid)

    const lookUpPost = db.prepare(`SELECT * FROM posts WHERE id = ?`)
    const ourPost = lookUpPost.get(result.lastInsertRowid)

    res.redirect("/post/" + ourPost.id)
})
    

app.post("/login", (req, res) => {
    const errors = [];

    let { username, password } = req.body;

    username = typeof username === "string" ? username.trim() : "";
    password = typeof password === "string" ? password : "";

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



    if (errors.length > 0) {
        return res.render("login", { error: errors, username });
    }

    const lookUpUser = db.prepare(`SELECT * FROM users WHERE username = ?`)
    const ourUser = lookUpUser.get(username)

    if (!ourUser) {
        errors.push("User not found")
        return res.render("login", { error: errors, username });
    }

    const isPasswordValid = bcrypt.compareSync(password, ourUser.password)
    if (!isPasswordValid) {
        errors.push("Invalid password")
        return res.render("login", { error: errors, username });
    }

    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60, skyColor: "blue", userid: ourUser.id, username: ourUser.username }, process.env.JWTSECRET)

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000
    });

    res.redirect("/")

}); 

app.post("/register", (req, res) => {
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
    const usernameStatement = db.prepare(`SELECT * FROM users WHERE username = ?`)
    const usernameResult = usernameStatement.get(username)
    if (usernameResult) {
        errors.push("Username already exists");
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
        return res.render("homepage", { error: errors, username });
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const insertUser = db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`)
    const result = insertUser.run(username, hash)

    const lookUpUser = db.prepare(`SELECT * FROM users WHERE id = ?`)
    const ourUser = lookUpUser.get(result.lastInsertRowid)

    // log the user in by giving them a cookie
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60, skyColor: "blue", userid: ourUser.id, username: ourUser.username }, process.env.JWTSECRET)

    res.cookie("ourSimpleApp", ourTokenValue, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000
    });

    res.redirect("/")
});

// add cookies

app.listen(3000)