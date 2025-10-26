import express from "express"
import dotenv from "dotenv"
import cors from "cors"
import helmet from "helmet"
import mongoSanitize from "express-mongo-sanitize"
import rateLimit from "express-rate-limit"
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
import chalk from "chalk"

dotenv.config()
cloudinaryConfig()
const app = express()

app.set('trust proxy', 1);
const PORT = process.env.PORT || 8000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
            scriptSrc: ["'self'"],
            connectSrc: ["'self'", "https://api.stripe.com"]
        }
    }
}));

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per windowMs
    message: 'Too many authentication attempts, please try again 15 minutes later',
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limiting for general API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/AdminLogin', authLimiter);
app.use('/api/AdminRegister', authLimiter);
app.use('/api', apiLimiter);

// Sanitize user input
app.use(mongoSanitize());

const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:5173", "https://avgallery.shop","https://www.avgallery.shop","https://avgallery.netlify.app"],
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        credentials: true
    }
});

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

app.use(express.static(path.join(__dirname,"uploads")))
app.use(cors( {origin: ["http://localhost:5173", "https://avgallery.shop",
"https://www.avgallery.shop","https://avgallery.netlify.app"],
methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],credentials: true}))
app.use('/api/payments/webhook', express.raw({type: 'application/json'}))
app.use(express.json({ limit: '10mb' })) // Reduced from 40mb for security

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
    console.log(chalk.blue("Server listening on port " + PORT))
    console.log(chalk.green("WebSocket server ready for real-time updates"))
    })