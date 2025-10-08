# Art Vista Gallery - Backend

Node.js/Express.js backend API for Art Vista Gallery e-commerce platform.

## Features
- User authentication (JWT)
- Product management
- Payment processing (Stripe)
- Email notifications
- File uploads (Cloudinary)
- Real-time notifications (Socket.IO)
- Multi-currency support

### 📧 Communication Services
- Brevo/Sendinblue email integration
- Automated email notifications
- Password reset emails
- Order confirmation emails
- Account verification emails

### 🔄 Real-time Features
- Socket.IO integration
- Live order status updates
- Real-time payment notifications
- Admin broadcasting system

### 🖼️ Media Management
- Cloudinary integration
- Image upload and optimization
- Secure file handling
- Automatic image transformation

## 🛠️ Tech Stack

| Category | Technology |
|----------|------------|
| **Runtime** | Node.js 18+ |
| **Framework** | Express.js |
| **Database** | MongoDB with Mongoose ODM |
| **Authentication** | JSON Web Tokens (JWT) |
| **Payment** | Stripe API |
| **Email** | Brevo/Sendinblue API |
| **File Storage** | Cloudinary |
| **Real-time** | Socket.IO |
| **Security** | bcrypt, CORS, Helmet |
| **Environment** | dotenv |

## 🚀 Quick Start

### Prerequisites
- Node.js (v18 or higher)
- MongoDB Atlas account or local MongoDB instance
- Stripe account for payment processing
- Cloudinary account for image storage
- Brevo/Sendinblue account for email services

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Paarisena/Capstone-Backend.git
   cd Capstone-Backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configurations (see Environment Setup section)
   ```

4. **Start the development server**
   ```bash
   npm start
   # Server will start on http://localhost:8000
   ```

5. **Verify installation**
   ```bash
   curl http://localhost:8000/health
   # Should return: {"status": "OK", "message": "Server is running"}
   ```

## 🔧 Environment Setup

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
PORT=8000
NODE_ENV=development

# Database Configuration
DB_USER=your_mongodb_username
DB_PASSWORD=your_mongodb_password
DB_CLUSTER=cluster0.p9fbzh6.mongodb.net
DB_CLUSTER_NAME=Capstone

# Authentication
SECRET_TOKEN=your_jwt_secret_key_here
JWT_EXPIRES_TIME=7d
COOKIE_EXPIRES_TIME=7

# Email Configuration (Brevo/Sendinblue)
BREVO_API_KEY=your_brevo_api_key_here
SENDER_NAME=Art Vista Gallery
SENDER_EMAIL=noreply@avgallery.shop

# Alternative SMTP Configuration
SMTP_HOST=live.smtp.mailtrap.io
SMTP_PORT=587
SMTP_USER=api
SMTP_PASS=your_smtp_password
SMTP_FROM_EMAIL=mailtrap@demomailtrap.com

# Payment Configuration (Stripe)
STRIPE_API_KEY=sk_test_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
PUBLISHABLE_KEY=pk_test_your_stripe_publishable_key

# File Storage (Cloudinary)
CLOUDINARY_NAME=your_cloudinary_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret

# Application URLs
BACKEND_URL=http://localhost:8000
FRONTEND_URL=http://localhost:5173
RESET_LINK=http://localhost:5173/reset-password
RESET_LINK_ADMIN=http://localhost:5173/admin-reset-password
VERIFICATION_LINK=http://localhost:5173/verification
VERIFICATION_LINK_ADMIN=http://localhost:5173/admin-verification
```

## 📚 API Documentation

### Base URL
```
Development: http://localhost:8000
Production: https://your-backend-domain.com
```

### Authentication Routes (`/api`)

#### User Registration
```http
POST /api/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123",
  "confirmpassword": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully. Please verify your email.",
  "requiresVerification": true
}
```

#### User Login
```http
POST /api/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "jwt_token_here",
  "user": {
    "_id": "user_id",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

#### Email Verification
```http
POST /api/verify-login
Content-Type: application/json

{
  "email": "john@example.com",
  "verificationCode": "123456",
  "isAdmin": false
}
```

#### Admin Authentication
```http
POST /api/AdminRegister    # Admin registration
POST /api/AdminLogin       # Admin login
```

#### Password Management
```http
POST /api/forgot-password
Content-Type: application/json

{
  "email": "john@example.com",
  "isAdmin": false
}
```

```http
POST /api/reset-password
Content-Type: application/json

{
  "token": "reset_token_from_email",
  "newPassword": "newpassword123",
  "isAdmin": false
}
```

### Product Management Routes (`/api`)

```http
GET    /api/getproducts              # Get all products
GET    /api/getproduct/:id           # Get single product
POST   /api/addproduct               # Add new product (Admin only)
PUT    /api/updateproduct/:id        # Update product (Admin only)
DELETE /api/deleteproduct/:id        # Delete product (Admin only)
```

#### Add Product Example
```http
POST /api/addproduct
Authorization: Bearer admin_jwt_token
Content-Type: multipart/form-data

{
  "productName": "Abstract Canvas Art",
  "productDescription": "Beautiful abstract painting",
  "Price": 299.99,
  "category": "Abstract",
  "stock": 10,
  "image": [file upload]
}
```

### Review System Routes (`/api`)

```http
GET    /api/products/:id/reviews     # Get product reviews
POST   /api/products/:id/reviews     # Add review (Auth required)
DELETE /api/products/:id/reviews     # Delete review (Auth required)
```

### Payment Routes (`/api/payments`)

```http
POST /api/payments/create-payment-intent    # Create Stripe payment intent
POST /api/payments/webhook                  # Stripe webhook endpoint
GET  /api/payments/user/:userId             # Get user's payment history
GET  /api/payments/payment/:orderId         # Get specific payment details
```

#### Create Payment Intent Example
```http
POST /api/payments/create-payment-intent
Authorization: Bearer user_jwt_token
Content-Type: application/json

{
  "cartItems": [
    {
      "productId": "product_id_here",
      "quantity": 1,
      "price": 299.99,
      "productName": "Abstract Canvas Art"
    }
  ],
  "amount": 299.99,
  "currency": "usd",
  "shippingAddress": {
    "street": "123 Main St",
    "city": "New York",
    "state": "NY",
    "zipCode": "10001",
    "country": "US"
  },
  "userId": "user_id_here"
}
```

### Health Check
```http
GET /health

Response:
{
  "status": "OK",
  "message": "Server is running",
  "timestamp": "2025-10-08T10:00:00.000Z",
  "uptime": 3600
}
```

## 🗄️ Database Schema

### User Collection
```javascript
{
  _id: ObjectId,
  name: String,
  email: String (unique, indexed),
  password: String, // bcrypt hashed
  isEmailVerified: Boolean,
  loginVerificationCode: String,
  loginVerificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: Date,
  updatedAt: Date
}
```

### Admin Collection
```javascript
{
  _id: ObjectId,
  name: String,
  email: String (unique, indexed),
  password: String, // bcrypt hashed
  isEmailVerified: Boolean,
  loginVerificationCode: String,
  loginVerificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: Date,
  updatedAt: Date
}
```

### Product Collection
```javascript
{
  _id: ObjectId,
  productName: String,
  productDescription: String,
  Price: Number,
  category: String,
  imageUrl: String, // Cloudinary URL
  stock: Number,
  featured: Boolean,
  reviews: [{
    userId: ObjectId,
    userName: String,
    rating: Number (1-5),
    comment: String,
    createdAt: Date
  }],
  createdAt: Date,
  updatedAt: Date
}
```

### Payment Collection
```javascript
{
  _id: ObjectId,
  userId: ObjectId,
  orderId: String (unique), // Stripe payment intent ID
  transactionId: String,
  amount: Number,
  currency: String,
  paymentMethod: String,
  paymentStatus: String, // pending, succeeded, failed, refunded
  items: [{
    productId: ObjectId,
    productName: String,
    quantity: Number,
    price: Number
  }],
  shippingAddress: {
    street: String,
    city: String,
    state: String,
    zipCode: String,
    country: String
  },
  createdAt: Date,
  updatedAt: Date
}
```

## 📁 Project Structure

```
Backend/
├── 📁 Config/
│   └── Cloudinary.js              # Cloudinary configuration
├── 📁 DB/
│   ├── model.js                   # Mongoose models (User, Admin, Product, Payment)
│   ├── mongoDB.js                 # MongoDB connection setup
│   └── Moongoose-connection.js    # Mongoose configuration
├── 📁 Login page/
│   ├── registration.js            # Authentication routes (register, login, verify)
│   ├── Payments.js               # Payment processing routes
│   ├── Dashboard.js              # Email service functions
│   └── CartModel.js              # Cart-related operations
├── 📁 Middleware/
│   ├── adminAuth.js              # Admin authentication middleware
│   └── Multer.js                 # File upload middleware
├── 📁 Routes/
│   └── ProductRoutes.js          # Product CRUD operations
├── 📁 uploads/                   # Temporary file storage
├── app.js                        # Main application entry point
├── package.json                  # Dependencies and scripts
├── .env                          # Environment variables (not in repo)
├── .env.example                  # Environment variables template
└── README.md                     # This file
```

## 🔒 Authentication

### JWT Implementation
The API uses JSON Web Tokens for authentication with the following structure:

```javascript
// Token Payload
{
  id: user._id,
  name: user.name,
  email: user.email,
  isAdmin: boolean,
  iat: timestamp,
  exp: timestamp
}

// Token Generation
const token = jwt.sign(payload, process.env.SECRET_TOKEN, { expiresIn: "7d" });
```

### Authentication Middleware
Protected routes require a valid JWT token in the Authorization header:

```javascript
Authorization: Bearer <jwt_token>
```

### Security Features
- Password hashing with bcrypt (10 salt rounds)
- Email verification for account activation
- Secure password reset with time-limited tokens
- Rate limiting on sensitive endpoints
- CORS protection
- Input validation and sanitization

## 💳 Payment Integration

### Stripe Configuration
The application integrates with Stripe for secure payment processing:

```javascript
// Payment Intent Creation
const paymentIntent = await stripe.paymentIntents.create({
  amount: totalAmount * 100, // Amount in cents
  currency: 'usd',
  metadata: {
    orderId: order._id.toString(),
    userId: userId
  }
});
```

### Webhook Security
Stripe webhooks are verified using webhook signatures:

```javascript
const sig = req.headers['stripe-signature'];
const event = stripe.webhooks.constructEvent(
  req.body, 
  sig, 
  process.env.STRIPE_WEBHOOK_SECRET
);
```

### Supported Payment Events
- `payment_intent.succeeded` - Payment completed successfully
- `payment_intent.payment_failed` - Payment failed
- `payment_intent.canceled` - Payment canceled
- `charge.dispute.created` - Chargeback initiated

## 📧 Email Services

### Brevo Integration
The application uses Brevo (formerly Sendinblue) for transactional emails:

```javascript
const apiInstance = new brevo.TransactionalEmailsApi();
apiInstance.authentications['apiKey'].apiKey = process.env.BREVO_API_KEY;
```

### Email Templates
- **Account Verification**: Welcome email with verification code
- **Password Reset**: Secure reset link with expiration
- **Login Verification**: Two-factor authentication codes
- **Order Confirmation**: Payment and order details
- **Admin Notifications**: Important system alerts

### Email Types
1. **Verification Emails**: 6-digit codes valid for 10 minutes
2. **Reset Emails**: Secure tokens valid for 1 hour
3. **Notification Emails**: Order updates and confirmations

## 🖼️ File Upload

### Cloudinary Integration
Images are uploaded and managed through Cloudinary:

```javascript
// Upload Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Image Transformation
{
  folder: 'art-vista-gallery',
  transformation: [
    { width: 800, height: 600, crop: 'fill' },
    { quality: 'auto', format: 'auto' }
  ]
}
```

### Supported Formats
- Image formats: JPEG, PNG, WebP, AVIF
- Maximum file size: 10MB
- Automatic optimization and compression
- Multiple resolution generation

## 🔄 Real-time Features

### Socket.IO Implementation
Real-time communication for:

```javascript
// Connection Handling
io.on('connection', (socket) => {
  // User authentication
  socket.on('authenticate', (userData) => {
    // Join user-specific rooms
    socket.join(`user_${userData.userId}`);
  });
  
  // Payment status updates
  socket.on('payment_status_update', (data) => {
    socket.to(`user_${data.userId}`).emit('payment_confirmed', data);
  });
});
```

### Real-time Events
- Payment status updates
- Order confirmation notifications
- Admin broadcasting
- User activity tracking

## 🚀 Deployment

### Environment Configuration

#### Development
```bash
NODE_ENV=development
PORT=8000
```

#### Production
```bash
NODE_ENV=production
PORT=10000 # Or assigned by hosting service
```

### Deployment Platforms

#### Render.com (Recommended)
1. Connect GitHub repository
2. Set environment variables in dashboard
3. Configure build and start commands:
   ```
   Build Command: npm install
   Start Command: npm start
   ```

#### Railway
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

#### Heroku
```bash
# Create Heroku app
heroku create art-vista-gallery-backend

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set SECRET_TOKEN=your_production_jwt_secret

# Deploy
git push heroku main
```

### Production Checklist
- [ ] Set `NODE_ENV=production`
- [ ] Use production database cluster
- [ ] Configure secure JWT secrets
- [ ] Set up SSL/HTTPS
- [ ] Configure proper CORS origins
- [ ] Set up monitoring and logging
- [ ] Configure Stripe webhooks for production domain
- [ ] Verify email service configuration

## 🧪 Testing

### Manual API Testing

#### Health Check
```bash
curl http://localhost:8000/health
```

#### User Registration
```bash
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "email": "test@example.com",
    "password": "password123",
    "confirmpassword": "password123"
  }'
```

#### User Login
```bash
curl -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

#### Protected Route (with token)
```bash
curl -X GET http://localhost:8000/api/getproducts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Error Handling
The API returns consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "error": "Detailed error information"
}
```

### Common HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (invalid/missing token)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `409` - Conflict (duplicate email, etc.)
- `500` - Internal Server Error

## 📊 Monitoring and Logging

### Built-in Health Monitoring
```javascript
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version
  });
});
```

### Logging Best Practices
- Request/response logging
- Error tracking and reporting
- Performance monitoring
- Database query optimization
- Security event logging

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and test thoroughly
4. Commit with descriptive messages: `git commit -m "Add new feature"`
5. Push to your fork: `git push origin feature/new-feature`
6. Create a Pull Request

### Code Style Guidelines
- Use consistent indentation (2 spaces)
- Follow JavaScript ES6+ standards
- Add JSDoc comments for functions
- Use meaningful variable and function names
- Implement proper error handling
- Write unit tests for new features

### Commit Message Format
```
type(scope): description

Examples:
feat(auth): add email verification
fix(payment): resolve webhook signature validation
docs(readme): update API documentation
refactor(db): optimize database queries
```

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Failed
```
Error: MongoServerError: Authentication failed
```
**Solution**: Verify MongoDB credentials and network access

#### Email Sending Failed
```
Error: Sender email not validated
```
**Solution**: Verify sender email in Brevo dashboard or use verified domain

#### JWT Token Invalid
```
Error: JsonWebTokenError: invalid signature
```
**Solution**: Check JWT secret in environment variables

#### Stripe Webhook Failed
```
Error: Webhook signature verification failed
```
**Solution**: Verify webhook secret and ensure raw body parsing

#### File Upload Failed
```
Error: Cloudinary upload failed
```
**Solution**: Check Cloudinary credentials and file size limits

### Debug Mode
Enable detailed logging by setting:
```env
NODE_ENV=development
DEBUG=true
```

## 📞 Support

### Documentation
- **API Documentation**: Available at `/api-docs` when server is running
- **Postman Collection**: Import collection for easy API testing
- **Swagger UI**: Interactive API documentation

### Contact Information
- **Email**: support@avgallery.shop
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/Paarisena/Capstone-Backend/issues)
- **Developer**: Paarisena Chakravarthy Gabriel

### Useful Links
- **Frontend Repository**: [Capstone-Frontend](https://github.com/Paarisena/Capstone-Frontend)
- **Live Demo**: [Art Vista Gallery](https://www.avgallery.shop)
- **API Documentation**: [API Docs](https://capstone-backend-4d9i.onrender.com/api-docs)

## 📄 License

This project is licensed 

---

## 🙏 Acknowledgments

- **Stripe** for secure payment processing
- **Cloudinary** for image management
- **MongoDB Atlas** for database hosting
- **Brevo** for email services
- **Render** for backend hosting

---

**Art Vista Gallery Backend** - Powering beautiful art experiences with robust, scalable technology. 🎨✨

Made with ❤️ by [Paarisena Chakravarthy Gabriel](https://www.linkedin.com/in/paarisena-chakravarthy-gabriel-a40a858b/)