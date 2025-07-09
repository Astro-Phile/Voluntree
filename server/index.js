require('dotenv').config();
const express = require('express');
const app = express();
const port = 5000;
const Mongoose = require('mongoose');
const validator = require('validator');
const saltRounds = 10;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const requiredVars = ['MONGO_URI','JWT_SECRET'];
requiredVars.forEach((key) => {
  if (!process.env[key]) {
    console.error(`❌ Missing required environment variable: ${key}`);
    process.exit(1);
  }
});

console.log('✅ Environment variables loaded successfully.');

Mongoose.connect(process.env.MONGO_URI);

const userSchema = new Mongoose.Schema({
  email:{
    type:String,
    required:true,
    unique:true
  },
  name:{
    type:String,
    required:true
  },
  type:{
    type:String,
    required:true,
    enum:['Volunteer', 'Organiser']
  },
  password:{
    type:String,
    required:true
  }
})

const User = Mongoose.model('User',userSchema)


app.use(express.urlencoded({extended:true}))
app.use(cookieParser());
app.get("/",(req,res)=>{
  res.send("works")
})

app.get("/profile",(req,res)=>{
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).send("Error: Missing token");
    
  }

  try {
    const result = jwt.verify(token,process.env.JWT_SECRET);
    res.send(`Welcome:${result.name}`)
  } catch(err) {
    return res.status(401).send('Error: Invalid token');
    
  };
})


app.post("/auth/signup",async (req,res)=>{
  const {email,name,type} = req.body;
  const plainPassword = req.body.password

  if (!email || !name || !type || !plainPassword) {
  return res.status(400).send("Required fields missing");
  
  }


  if (!validator.isEmail(email)) {
    return res.status(400).send("Error:Invalid Email.");
    
  };
  

  const userDoc = await User.findOne({email:email});

  if (userDoc) {
    return res.status(400).send("Email already exists, login instead.");
    
  };
  
  try {
    const password = await bcrypt.hash(plainPassword,saltRounds)

    const newUser = new User({
      email:email,
      name:name,
      type:type,
      password:password
    });
    await newUser.save();

    const token = jwt.sign({
      name:newUser.name,
      email:newUser.email,
      type:newUser.type
    }, process.env.JWT_SECRET,{expiresIn:'1h'});
    
    res.cookie('token',token,{maxAge:60*60*1000});
    res.redirect("/profile")


  } catch (err) {
    res.status(500).send('Server Error.');
    return console.error(err);
    
  }
});

app.post("/auth/login",async (req,res)=>{
  const {email,password} = req.body;
  if (!email || !password) {
  return res.status(400).send("Error: Email and password are required.");
  
  }

  if (!validator.isEmail(email)) {
    return res.status(400).send("Error:Invalid Email.");
    
  };  

  const userDoc = await User.findOne({email:email});
  if (!userDoc) {
    return res.status(400).send("Invalid email, signup first.");
    
  }
  const result = await bcrypt.compare(password,userDoc.password);
  if (!result) {
    return res.status(400).send('Incorrect password, try again');
    
  }
try {
    const token = jwt.sign({
    name:userDoc.name,
    email:userDoc.email,
    type:userDoc.type
  }, process.env.JWT_SECRET,{expiresIn:'1h'});

    res.cookie('token',token,{maxAge:60*60*1000});
    res.redirect("/profile")
} catch (err) {
  return res.status(500).send("Server error");
  
}

});


app.get('/health', (req, res) => {
  res.json({ status: "ok" });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});