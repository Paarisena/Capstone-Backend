import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import jwt from "jsonwebtoken"
import mongooseconnect from "./DB/Moongoose-connection.js"
import connecttodb from "./DB/mongoDB.js"
import regis from "./Login page/registration.js"


dotenv.config()
const app = express()
const PORT = process.env.PORT || 8000;

app.use(express.json())
app.use(cors())

const AllApi = (req,res,next) => {
    try{
        const token = req.headers("Authoraization")
        jwt.verify(token,process.env.SECRET_TOKEN)
        next()
    }catch{
        res.status(401).json({message:"Unauthorised"})
    }
}
app.use("/api",regis)


await connecttodb()
await mongooseconnect()




app.listen(PORT,()=>{
    console.log("Server listerning success" + PORT)
    })