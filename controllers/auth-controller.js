const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// register controller
const registerUser = async(req, res) => {
try{
   
  //extract user information from req.body
  const { username, email, password, role } = req.body;

  //check if the user is already exists in our database
  const checkExistingUser = await User.findOne({ 
    $or : [ {username}, {email} ],
    });

  if(checkExistingUser){
    return res.status(400).json({
      success: false,
      message: "User already exists with this username or email"
    });
  }

  //hash user password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

  //create a new user and save in your database
    const newlyCreatedUser = new User({
      username,
      email,
      password: hashedPassword,
      role: role || "user",
    });
    
    await newlyCreatedUser.save();

    if(newlyCreatedUser){
      res.status(201).json({
        success: true,
        message: "User registered successfully",
      })
    }else {
        res.status(400).json({
        success: false,
        message: "Unable to register user! please try again.",
      });
    }

}catch(error){
  console.log(error);
  res.status(500).json({
    success: false,
    message: "Server Error"
  });
}
};





// login controller

const loginUser = async(req, res) => {
  try{
    const { username, password } = req.body;

    //check if the user exists in our database
    const user = await User.findOne({ username });

    if(!user){
      return res.status(400).json({
        success: false,
        message: `user  doesn't exists`
      });
    }

    //if user exists, compare the password
    const isPassordMatch = await bcrypt.compare(password, user.password);

    if(!isPassordMatch){
      return res.status(400).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    

    //create user token 
    const accessToken = jwt.sign(
      {
        userId: user._id,
        username: user.username,
        role: user.role,
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "30m" }
    );

    res.status(200).json({
      success: true,
      message: "User logged in successfully",
      accessToken,
    });
  }catch(error){
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Server Error"
    });
}
};

const changePassword =  async (req, res) => {
  try {

    // Check if userInfo exists (from authMiddleware)
    // if(!req.userInfo || !req.userInfo.userId){
    //   return res.status(401).json({
    //     success: false,
    //     message: "Unauthorized. Please login to continue"
    //   });
    // }

    const userId = req.userInfo.userId;

    //extract old password and new password from req.body
    const { oldPassword, newPassword } = req.body;

    // Validate input
    // if(!oldPassword || !newPassword){
    //   return res.status(400).json({
    //     success: false,
    //     message: "Old password and new password are required"
    //   });
    // }

    //find current logged in user from database
    const user  = await User.findById(userId);

    if(!user){
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    //check if old password is correct
    const isOldPasswordMatch = await bcrypt.compare(oldPassword, user.password);

    if(!isOldPasswordMatch){
      return res.status(400).json({
        success: false,
        message: "Old password is incorrect"
      });
    }

    //hash new password
    const salt = await bcrypt.genSalt(10);
    const newHashedPassword = await bcrypt.hash(newPassword, salt);

    //update user password in database
    user.password = newHashedPassword;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully"
    });

  }catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Server Error"
    });
  }
}


module.exports = { registerUser, loginUser, changePassword };