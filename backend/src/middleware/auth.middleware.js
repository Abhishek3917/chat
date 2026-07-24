import jwt from "jsonwebtoken"
import User from "../models/user.model.js"

export const protectRoute = async (req,res,next) =>{
    const token = req.cookies.jwt()

    if(!token){
        res.status(401).json({message: "Unautorized acess not token found"})
    }

    
}