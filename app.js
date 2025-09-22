import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import cloudinaryConfig from "./Config/Cloudinary.js"
import jwt from "jsonwebtoken"
import mongooseconnect from "./DB/Moongoose-connection.js"
import connecttodb from "./DB/mongoDB.js"
import regis from "./Login page/registration.js"
import ProductRouter from "./Routes/ProductRoutes.js"
import path from "path"
import{ fileURLToPath } from "url"


dotenv.config()
cloudinaryConfig()
const app = express()
const PORT = process.env.PORT || 8000;

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

app.use(express.static(path.join(__dirname,"uploads")))
app.use(express.json(({ limit: '40mb' })))
app.use(cors( {origin: "http://localhost:5173",credentials: true}))

app.use("/api",regis)
app.use("/api",ProductRouter)


await connecttodb()
await mongooseconnect()




app.listen(PORT,()=>{
    console.log("Server listerning success" + PORT)
    })