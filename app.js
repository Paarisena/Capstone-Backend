import express from "express"
import cookieParser from "cookie-parser"
import session from "express-session"
import dotenv from "dotenv"
import cors from "cors"
import helmet from "helmet"
import mongoSanitize from "express-mongo-sanitize"
import rateLimit from "express-rate-limit"
import { createServer } from "http"
import { Server } from "socket.io"
import cloudinaryConfig from "./Config/Cloudinary.js"
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

// Define allowed origins once at the top after imports
const allowedOrigins = [
    "http://localhost:5173", 
    "https://avgallery.shop",
    "https://www.avgallery.shop",
    "https://avgallery.shop",
];

const app = express()
app.set('trust proxy', 1);

const PORT = process.env.PORT || process.env.WEBSITES_PORT || 8000

// Configure CORS early
app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Accept',
        'Origin',
        'X-Requested-With'
    ],
    exposedHeaders: ['Set-Cookie'],
    credentials: true,
    maxAge: 86400, // 24 hours in seconds
    optionsSuccessStatus: 204
}));

app.use(cookieParser());

// Add preflight handler
app.options('*', cors());



// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'", "https://*.azurewebsites.net"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", 
                "https://api.stripe.com",
                "https://*.azurewebsites.net",
                ...allowedOrigins
            ],
            frameSrc: ["'self'", "https://*.stripe.com"]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
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


app.use(express.static(path.join(__dirname,"uploads")))
app.use('/api/payments/webhook', express.raw({type: 'application/json'}))
app.use(express.json({ limit: '10mb' })) 


app.use("/api", regis)
app.use("/api", ProductRouter)
app.use("/api/payments", payments)


const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        credentials: true
    }
});

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

app.set('io', io);

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// Initialize function
const initializeApp = async () => {
    try {
        await connecttodb();
        await mongooseconnect();
        
        server.listen(PORT, () => {
            console.log(chalk.blue(`Server listening on port ${PORT}`));
            console.log(chalk.green("WebSocket server ready for real-time updates"));
        });
    } catch (error) {
        console.error(chalk.red('Failed to initialize app:', error));
        process.exit(1);
    }
};

// Start the application
initializeApp().catch(console.error);

app.use((err, req, res, next) => {
    console.error(chalk.red('Error:', err.stack));
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal Server Error',
        error: process.env.NODE_ENV === 'development' ? err.stack : {}
    });
});

app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

export default app