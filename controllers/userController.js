const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const { log } = require("console");
const sendEmail = require("../utils/sendEmail");

const generateToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: "1d"})

};
//Register User
const registerUser =  asyncHandler( async (req, res) => {
    const {name, email, password} = req.body

    //validation
    if(!name || !email || !password){
        res.status(400)
        throw new Error("Pease fill in fields")
    }
    if (password.length < 6) {
        res.status(400);
        throw new Error('Password must be at least 6 characters');
    }
    //check for existing user
    const userExists = await User.findOne({email}) 

    if (userExists) {
        res.status(400)
        throw new Error("Email has  already been registered")
    }

    


    //create new user
    const user = await User.create({ 
        name,
        email,
        password,
    });

    //generate token
    const token = generateToken(user._id);

    //send http 0nly cookie

    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400),
        sameSite: "none",
        secure: true,
    });

    if (user) {
        const { _id, name, email, photo, phone, bio} = user
        res.status(201).json({
            _id, name, email, photo, phone, bio, token
        })
    } else {
        res.status(400)
        throw new Error("invalid user data")
    }


});

//Login User

const loginUser = asyncHandler( async (req, res) => {
    const {email, password} = req.body
    //validate request

    if (!email || !password) {
        res.status(400)
        throw new Error("Please add email and password");
    }

    //check if user exists in DB

    const user = await User.findOne({email})

    if (!user) {
        res.status(400)
        throw new Error("user not found please signup");
    }

    //check if password is correct( user exists)

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

     //generate token
     const token = generateToken(user._id);

     //send http 0nly cookie
 
     res.cookie("token", token, {
         path: "/",
         httpOnly: true,
         expires: new Date(Date.now() + 1000 * 86400),
         sameSite: "none",
         secure: true,
     });

    if (user && passwordIsCorrect) {
        const { _id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id, name, email, photo, phone, bio, token,
        });

        
    } else {
        res.status(400)
        throw new Error("Invalid emaill or password");
    }
});

//logout user

const logout = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    return res.status(200).json({ message: "Successfully logged out"})
});

//get user info

const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id)

    
    if (user) {
        const { _id, name, email, photo, phone, bio} = user;
        res.status(200).json({
            _id, name, email, photo, phone, bio
        })
    } else {
        res.status(400)
        throw new Error("user not found")
    }
    
});

//get login status

const loginStatus = asyncHandler (async (req, res) => {

    const token = req.cookies.token;
    if(!token) {
        return res.json(false);
    }
    
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if(verified) {
        return res.json(true);
    }
    return res.json(false);
});

//update user

const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if(user) {
        const { name, email, photo, phone, bio,} = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.photo = req.body.photo || photo;

        const updatedUser = await user.save()

        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name, 
            email: updatedUser.email, 
            photo: updatedUser.photo, 
            phone: updatedUser.phone, 
            bio: updatedUser.bio,
        })

    } else {
        res.status(404);
        throw new Error("User not found");
    }
});

const changePassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    const {oldPassword, password} = req.body;
    
    if(!user) {
        res.status(400);
        throw new Error("user not found, please signup");

    }
    //validate

    if(!oldPassword || !password) {
        res.status(400);
        throw new Error("please add old and new password");

    }
    //check if oldpassword matches password in the db
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password)

    //save new password

    if(user && passwordIsCorrect) {

        user.password = password
        await user.save()
        res.status(200).send("password changed successful")
    } else {
        res.status(400);
        throw new Error("old password is incorrect");

    }


    

});

const forgotPassword = asyncHandler(async (req, res) => {
    const {email} = req.body
    const user = await User.findOne({email})

    if(!user) {
        res.status(404)
        throw new Error("user doesnt exist");
    }

    //delete token if it exists in the DB
    let token = await Token.findOne({userId: user._id})
    if (token) {
        await token.deleteOne()
    }

    //create reset token

    let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken);

    //hash token before saving to db

    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    //save token to db

    await new Token({
        userId: user._id,
        token: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * (60 * 1000) //30 minutes
    }).save()

    //construct reset Url

    const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`

    //reset email

    const message = `
    <h2>Hello ${user.name}</h2>
    <p> this link is only valid for 30 minutes</p>

    <a href=${resetUrl} cicktracking=off>${resetUrl}</a>
    
    `
    

    const subject = "Password Reset Request"
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER

    try {
        await sendEmail(subject, message, send_to, sent_from);
        res.status(200).json({ success: true, message: "Reset Email Sent" });
      } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
      }
    });

    //Reset password

    const resetPassword = asyncHandler (async (req, res) => {
        const {password} = req.body
        const {resetToken} = req.params
//hash token then compare to the db
        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

        //find token in db
        const userToken = await Token.findOne({
            token: hashedToken,
            expiresAt: {$gt: Date.now()}
        })

        if(!userToken) {
            res.status(404);
            throw new Error('Invalid or Expired token');
        }

        //Find user
        const user = await User.findOne({_id: userToken.userId})
        user.password = password
        await user.save()
        res.status(200).json({
            message: "Password reset successful , please login"
        });

    });
module.exports = {
    registerUser,
    loginUser,
    logout,
    getUser,
    loginStatus,
    updateUser,
    changePassword,
    forgotPassword,
    resetPassword,
}