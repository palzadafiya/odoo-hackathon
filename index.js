import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/login", async (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    res.send("Logged In");
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/");
  }
});

app.post("/submit", async (req, res) => {
  if (req.isAuthenticated()) {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [
      req.body.secret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } else {
    res.redirect("/");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/dashboard",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const mail = req.body.mail;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      mail,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, mail, hash) VALUES ($1, $2, $3) RETURNING *",
            [username, mail, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Error logging in user:", err);
            } else {
              res.redirect("/dashboard");
            }
          });
        }
      });
    }
  } catch (err) {
    console.error(err);
  }
});

passport.use(
  new LocalStrategy(async (username, password, role, cb) => {
    try {
        var result;
        if(role === "user"){
            result = await db.query("SELECT * FROM users WHERE username = $1", [
                    username,
                ]);
        }else{
            result = await db.query("SELECT * FROM librarians WHERE username = $1", [
                username,
            ]);
        }
       
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.hash;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/dashboard",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE mail = $1", [
          profile.email
        ]);
        if(result.rows.length === 0){
            result = await db.query("SELECT * FROM librarians WHERE mail = $1", [
                profile.email
            ]);
        }
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username, mail, hash) VALUES ($1, $2, $3) RETURNING *",
            [profile.displayName, profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
