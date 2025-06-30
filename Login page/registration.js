import express from "express"
import * as bcrypt from "bcrypt"
import { user, admin, ReviewDatabase } from "../DB/model.js"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"
dotenv.config()

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
        res.status(200).json({message:"Login Successful",token
            })
    }catch(err){
        res.status(500).json({
            message:'Something went wrong',err})
    }
})

registration.post('/AdminRegister',async(req,res)=>{
    const {name,email,password,confirmpassword} = req.body;

    if(password !== confirmpassword){
        
        return res.status(400).json({message:'Password does not match'})
    }
    const hashedPassword = bcrypt.hashSync(password, 10);

    try{
        const existinguser = await admin.findOne( {email})
        if(existinguser){
            return res.status(400).json({
                message:'Username already Exist'})

        }
        
     
        const newuser1 = new admin({
            name,
            email,
            password:hashedPassword,
            
            
        })
        await newuser1.save();
        res.status(201).json({message:'User registered Succesfully'})
    } catch(err){
        res.status(500).json({message:'Server Error'})
    }
})


registration.post('/AdminLogin',async(req,res)=>{
    const{email,password} = req.body;
    try{
        const existinguser = await admin.findOne({email})
        if(!existinguser){
            return res.status(400).json({message:"User not exist"})
        }
        const ispasswordcorrect = await bcrypt.compare(password,existinguser.password)
        if(!ispasswordcorrect){
            return res.status(400).json({message:'Login Failed'})
            
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
            message:'Invalid credentials',err})
    }
})

registration.post('/products/:id/reviews', async (req, res) => {
    const id = req.params.id;
    const {name, rating, comment} = req.body;
    try {
        const existingReview = await ReviewDatabase.findOne({ productId: id, name });
        if (existingReview) {
            return res.status(400).json({ message: "You have already reviewed this product" });
        }
        const newReview = new ReviewDatabase({
            productId: id,
            name,
            rating,
            comment
        });
        await newReview.save();
        res.status(201).json({ success:true, message: "Review added successfully" });
    } catch (err) {
        console.error('Error adding review:', err);
        res.status(500).json({ message: "Internal server error" });
    }
}
);

registration.get('/products/:id/reviews', async (req, res) => {
    const id = req.params.id;
    try {
        const reviews = await ReviewDatabase.find({ productId: id });
        res.status(200).json({ success: true, reviews });;
    } catch (err) {
        console.error('Error fetching reviews:', err);
        res.status(500).json({ message: "Internal server error" });
    }
});

registration.delete('/products/:id/reviews', async (req, res) => {
    const id = req.params.id;
    const { name } = req.body;
    try {
        const review = await ReviewDatabase.findOneAndDelete({ productId: id, name });
        if (!review) {
            return res.status(404).json({ success: false, message: "Review not found" });
        }
        res.status(200).json({ success: true, message: "Review deleted successfully" });;
    } catch (err) {
        console.error('Error deleting review:', err);
        res.status(500).json({ message: "Internal server error" });
    }
});

export default registration

