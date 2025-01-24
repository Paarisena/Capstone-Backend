import express from "express"
import * as bcrypt from "bcrypt"
import { user } from "../DB/model.js"
import jwt from "jsonwebtoken"

const registration = express.Router()

registration.post('/register',async(req,res)=>{
    const {name,email,password,confirmpassword} = req.body;

    
    if(password !== confirmpassword){
        
        return res.status(400).json({message:'Password does not match'})
    }
    const hashedPassword = bcrypt.hashSync(password, 10);

    try{
        const existinguser = await user.findOne( {email})
        if(existinguser){
            return res.status(400).json({
                message:'Username already Exist'})

        }
        
     
        const newuser = new user({
            name,
            email,
            password:hashedPassword,
            
            
        })
        await newuser.save();
        res.status(201).json({message:'User registered Succesfully'})
    } catch(err){
        res.status(500).json({message:'Server Error'})
    }
})


registration.post('/login',async(req,res)=>{
    const {email,password} = req.body;

    try{
        const existinguser = await user.findOne({email})
        if(!existinguser){
            return res.status(400).json({message:'User does not exist'})
        }

        const ispasswordcorrect = await bcrypt.compare(password,existinguser.password)
        if(!ispasswordcorrect){
            return res.status(400).json({message:'Invalid credentials'})
            
        }
        const token = jwt.sign(
            {name: existinguser.name, email: existinguser.email},
            process.env.SECRET_TOKEN,
            {
                expiresIn:"15m"
            }
        )
        res.status(200).json({token
            })
    }catch(err){
        res.status(500).json({
            message:'Something went wrong',err})
    }
})

export default registration

