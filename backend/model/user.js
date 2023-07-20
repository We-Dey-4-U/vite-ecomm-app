//The mongoose library is used to define a schema that is mapped to a MongoDB 
//collection. In the schema, an email and password will be required for a user. 
//The mongoose library takes the schema and converts it into a model:

const mongoose = require("mongoose");
//bcrypt for hashing user passwords,
const bcrypt = require("bcryptjs");
//jsonwebtoken for signing tokens
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  name:{
    type: String,
    required: [true, "Please enter your name!"],
  },
  email:{
    type: String,
    required: [true, "Please enter your email!"],
  },
  password:{
    type: String,
    required: [true, "Please enter your password"],
    minLength: [4, "Password should be greater than 4 characters"],
    select: false,
  },
  phoneNumber:{
    type: Number,
  },
  addresses:[
    {
      country: {
        type: String,
      },
      city:{
        type: String,
      },
      address1:{
        type: String,
      },
      address2:{
        type: String,
      },
      zipCode:{
        type: Number,
      },
      addressType:{
        type: String,
      },
    }
  ],
  role:{
    type: String,
    default: "user",
  },
  avatar:{
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
 },
 createdAt:{
  type: Date,
  default: Date.now(),
 },
 resetPasswordToken: String,
 resetPasswordTime: Date,
});


//  Hash password  //bcrypt for hashing user passwords,
//You should avoid storing passwords in plain text because if an attacker manages 
//to get access to the database, the passwords can be read.
//To avoid this, you will use a package called bcrypt to hash user passwords 
//and store them safely. Add the library and the following lines of code:

//this a pre-hook function. Before the user information is saved in the database, 
//this function will be called, 
//you will get the plain text password, hash it, and store it
userSchema.pre(
  "save", async function (next){
  if(!this.isModified("password")){
    next();
  }

  this.password = await bcrypt.hash(this.password, 10);
});




// jwt token jsonwebtoken for signing tokens
userSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id}, process.env.JWT_SECRET_KEY,{
    expiresIn: process.env.JWT_EXPIRES,
  });
};

// compare password
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model("User", userSchema);