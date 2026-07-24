import { generateToken } from "../lib/utility.js"
import User from "../models/user.model.js"
import bcrypt from "bcryptjs"
import cloudinary from '../lib/cloudinary.js'

// signup
export const signup = async (req,res) =>{
    const {fullName,email,password} = req.body
    try {

        if(!fullName || !email || !password){
            return res.status(400).json({messag: "all fields are required"})
        }

        if(password.length < 6){
            return res.status(400).json({message: "password should be greater than 6"})
        }

        const user = await User.findOne({email})

        if (user){
            return res.status(400).json({message:"email is already"})
        }

        const salt = await bcrypt.genSalt(10)
        const hashpassword = await bcrypt.hash(password,salt)

        const newUser = new User({
            fullName,
            email,
            password:hashpassword
        })

        if(newUser){
            //jwt token
            await newUser.save()
            generateToken(newUser._id,res)
            
        } else{
            res.status(400).json({message:"invalid user data"})
        }

        res.status(201).json({
            _id:newUser._id,
            fullName:newUser.fullName,
            email:newUser.email,
            profilePic:newUser.profilePic,
        })

    } 
    
    catch (error) {
        console.log("Error in signupcontroller",error.message)
        res.status(500).json({message:"Internal server Error"})
    }
}
// login function
export const login = async (req,res) =>{
    const {email,password} = req.body
    try {
        const user = await User.findOne({email})

        if(!user){
            res.status(400).json({message:"invalide credentials"})
        }
        const ispasswordcorrect = await bcrypt.compare(password,user.password)

        if(!ispasswordcorrect){
            res.status(400).json({message:"invalide credentials"})
        }
        generateToken(user._id,res)

        res.status(200).json({
            _id:user._id,
            fullName:user.fullName,
            email:user.email,
            profilePic:user.profilePic,
        })


    } catch (error) {
        console.log("Error in logincontroller",error.message)
        res.status(500).json({message:"Internal server Error"})
    }
}

// logout
export const logout = (req,res) =>{
    try {
        res.cookie("jwt","",{maxAge:0})
        res.status(200).json({message:"logged out succesfully"})
    } catch (error) {
        console.log("Error in logoutcontroller",error.message)
        res.status(500).json({message:"Internal server Error"})        
    }
}

// updateprofile

export const updateProfile = async (req,res)=>{
    try {
        const {profilePic} = req.body;
        const userId = req.user._id

        if(!profilePic){
            return res.status(400).json({message:"image is required"})
        }

        const uploadResponse = await cloudinary.uploader.upload(profilePic);
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            {profilePic:uploadResponse.secure_url},
            {new:true}
        )
        res.status(200).json(updatedUser);
    } catch (error) {
        console.log("error in uplaod image",error)
        res.status(500).json({message:"Server error"})        
    }
}

// check auth
export const checkAuth = (req,res) =>{
    try {
        res.status(200).json(req.user)
    } catch (error) {
        console.log("Error in checkAuth",error.message)
        res.status(500).json({message:"Internal error"})
    }
}