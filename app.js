import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import { createServer } from "http"
import { Server } from "socket.io"
import cloudinaryConfig from "./Config/Cloudinary.js"
import jwt from "jsonwebtoken"
import mongooseconnect from "./DB/Moongoose-connection.js"
import connecttodb from "./DB/mongoDB.js"
import regis from "./Login page/registration.js"
import payments from "./Login page/Payments.js"
import ProductRouter from "./Routes/ProductRoutes.js"
import path from "path"
import{ fileURLToPath } from "url"


dotenv.config()
cloudinaryConfig()
const app = express()
const PORT = process.env.PORT || 8000;

const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:5173", "https://avgallery.shop","https://www.avgallery.shop","https://avgallery.netlify.app"],
        methods: ["GET", "POST"],
        credentials: true
    }
});

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

app.use(express.static(path.join(__dirname,"uploads")))
app.use(cors( {origin: ["http://localhost:5173", "https://avgallery.shop",
"https://www.avgallery.shop","https://avgallery.netlify.app"],credentials: true}))
app.use('/api/payments/webhook', express.raw({type: 'application/json'}))
app.use(express.json(({ limit: '40mb' })))

app.set('io', io);

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

app.use("/api",regis)

app.use("/api",ProductRouter)

app.use("/api/payments",payments)

await connecttodb()
await mongooseconnect()

server.listen(PORT,()=>{
    console.log("Server listening on port " + PORT)
    console.log("WebSocket server ready for real-time updates")
    })