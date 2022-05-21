const express = require('express')
const mongoose = require('mongoose')
const morgan = require('morgan')
const bodyParser = require('body-parser')
mongoose.connect('mongodb://localhost:27017/DEMO',{useNewUrlParser: true , useUnifiedTopology: true})
require("dotenv").config();
const db = mongoose.connection

const  joi = require('@hapi/joi')

const signUp = joi.object({
  first_name:joi.string().min(3).required(),
  last_name:joi.string().min(3).required(),
  email:joi.string().min(4).required().email(),
  password:joi.string().min(6).required()
});
const login = joi.object({
  email:joi.string().min(4).required().email(),
  password:joi.string().min(6).required()
});
var bcrypt = require('bcryptjs');
var jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");


const User = require("./model/user");

db.on('error',(err) => {
    console.log(err)
})

db.once('open',() => {
    console.log('Success....')
})

const app = express()
app.use(morgan('dev'))
app.use(bodyParser.urlencoded({extended:true}))
app.use(bodyParser.json())
app.use(express.json());

const PORT = process.env.PORT  || 3000 

app.listen(PORT , () => {
    console.log(PORT)
})

app.post("/register", async (req, res) => {

    // Our register logic starts here
    try {

      const { error } = signUp.validate(req.body);
      // Error in response
      res.send(error.details[0].message);
      // Get user input
      const { first_name, last_name, email, password } = req.body;
  
      // Validate user input
      if (!(email && password && first_name && last_name)) {
        res.status(400).send("All input is required");
      }
  
      // check if user already exist
      // Validate if user exist in our database
      const oldUser = await User.findOne({ email });
  
      if (oldUser) {
        return res.status(409).send("User Already Exist. Please Login");
      }
  
      //Encrypt user password
      encryptedPassword = await bcrypt.hash(password, 10);
  
      // Create user in our database
      const user = await User.create({
        first_name,
        last_name,
        email: email.toLowerCase(), // sanitize: convert email to lowercase
        password: encryptedPassword,
      });
  
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "30s",
        }
      );
      // save user token
      user.token = token;
  
      // return new user
      res.status(201).json(user);
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
  });
  
  app.post("/login", async (req, res) => {

    // Our login logic starts here
    try {

      const { error } = login.validate(req.body);
      // Error in response
      res.send(error.details[0].message);
      // Get user input
      const { email, password } = req.body;
  
      // Validate user input
      if (!(email && password)) {
        res.status(400).send("All input is required");
      }
      // Validate if user exist in our database
      const user = await User.findOne({ email });
  
      if (user && (await bcrypt.compare(password, user.password))) {
        // Create token
        const token = jwt.sign(
          { user_id: user._id, email },
          process.env.TOKEN_KEY,
          {
            expiresIn: "30s",
          }
        );
  
        // save user token
        user.token = token;
  
        // user
        res.status(200).json(user);
      }
      res.status(400).send("Invalid Credentials");
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
  });

  app.post("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome 🙌 ");
  });