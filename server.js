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
import ComplianceRouter from "./Routes/ComplianceRoutes.js"
import path from "path"
import{ fileURLToPath } from "url"
import chalk from "chalk"
import { performHealthCheck, complianceMonitor } from "./security-fixes/soc-monitoring.js"

dotenv.config()
cloudinaryConfig()

// Debug environment variables
console.log('Environment:', {
    NODE_ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    DB_CLUSTER: process.env.DB_CLUSTER ? 'Set' : 'Not Set',
    DB_CLUSTER_NAME: process.env.DB_CLUSTER_NAME ? 'Set' : 'Not Set',
    DB_USER: process.env.DB_USER ? 'Set' : 'Not Set',
    CLOUDINARY_NAME: process.env.CLOUDINARY_NAME ? 'Set' : 'Not Set',
    BREVO_API_KEY: process.env.BREVO_API_KEY ? 'Set' : 'Not Set',
    STRIPE_API_KEY: process.env.STRIPE_API_KEY ? 'Set' : 'Not Set'
});

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)


const allowedOrigins = [
    "http://localhost:5173", 
    "https://www.avgallery.shop"
];

const app = express()
app.set('trust proxy', 1);

// Add request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

const PORT = process.env.PORT || 8000

// Configure CORS early
app.use(cors({
    origin: true, // Allow all origins temporarily for debugging
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

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'", "http://localhost:5173"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", 
                "https://api.stripe.com",
                "http://localhost:5173",
                ...allowedOrigins
            ],
            frameSrc: ["'self'", "https://*.stripe.com"]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Sanitize user input
app.use(mongoSanitize());

app.use(express.static(path.join(__dirname,"uploads")))
app.use('/api/payments/webhook', express.raw({type: 'application/json'}))
app.use(express.json({ limit: '10mb' })) 

// Root route handler (BEFORE rate limiters)
app.get('/', (req, res) => {
    res.status(200).json({ message: 'AVGallery API is running' });
});

// Health check endpoint (BEFORE rate limiters - NO rate limiting)
app.get('/api/health', async (req, res) => {
    try {
        const health = await performHealthCheck();
        res.status(200).json(health);
    } catch (error) {
        console.error('Health check error:', error);
        res.status(503).json({
            status: 'DOWN',
            timestamp: new Date().toISOString(),
            error: error.message
        });
    }
});

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // Increased for development/testing
    message: 'Too many authentication attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for localhost in development
        const isLocalhost = req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1';
        return process.env.NODE_ENV === 'development' && isLocalhost;
    }
});

// Rate limiting for general API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
});

// Relaxed rate limiting for compliance endpoints
const complianceLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 500, // Very high limit for real-time dashboard
    message: 'Too many compliance requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for localhost in development
        const isLocalhost = req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1';
        return process.env.NODE_ENV === 'development' && isLocalhost;
    }
});

// Apply rate limiting to specific routes (AFTER health check)
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/AdminLogin', authLimiter);
app.use('/api/AdminRegister', authLimiter);
app.use('/api/compliance', complianceLimiter); // Relaxed for compliance dashboard
app.use('/api', apiLimiter);

// API Routes
app.use("/api", regis)
app.use("/api", ProductRouter)
app.use("/api/compliance", ComplianceRouter)
app.use("/api/payments", payments)


const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        credentials: true
    }
});

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
        // Connect to databases
        console.log(chalk.yellow('🔄 Connecting to databases...'));
        await connecttodb();
        await mongooseconnect();
        console.log(chalk.green('✅ Databases connected'));
        
        // Start compliance monitoring AFTER database is ready
        console.log(chalk.yellow('🔄 Starting SOC compliance monitoring...'));
        complianceMonitor.startMonitoring();
        console.log(chalk.green('✅ Compliance monitoring active'));
        
        // Start server
        server.listen(PORT, () => {
            console.log(chalk.blue(`✅ Server listening on port ${PORT}`));
            console.log(chalk.green("✅ WebSocket server ready for real-time updates"));
            console.log(chalk.green(`✅ Health check: http://localhost:${PORT}/api/health`));
            console.log(chalk.green(`✅ Compliance dashboard: http://localhost:5173/admin/compliance`));
        });
    } catch (error) {
        console.error(chalk.red('❌ Failed to initialize app:', error));
        process.exit(1);
    }
};

// Start the application
initializeApp().catch(console.error);

app.use((err, req, res, next) => {
    console.error(chalk.red('🚨 Error occurred:'));
    console.error(chalk.red('Error name:', err.name));
    console.error(chalk.red('Error message:', err.message));
    console.error(chalk.red('Error stack:', err.stack));
    console.error(chalk.red('Request path:', req.path));
    console.error(chalk.red('Request method:', req.method));
    
    // Send detailed error in production temporarily for debugging
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal Server Error',
        error: {
            name: err.name,
            message: err.message,
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
            path: req.path,
            method: req.method
        }
    });
});

app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

export default app