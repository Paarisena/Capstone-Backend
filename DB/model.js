import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
 
    name:{
        type:String,
        required: true
    },
    email:{
        type:String,
        required: true
    },
    password:{
        type:String,
        required:true
    },
    cart: {
        type: Object,
        default: {},
    },
    // Add these fields for password reset
    resetPasswordToken: {
        type: String,
        default: null
    },
    resetPasswordExpires: {
        type: Date,
        default: null
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    loginVerificationCode: {
    type: String
},
loginVerificationExpires: {
    type: Date
}

})

const user = new mongoose.model("user", userSchema,"users" )

const adminSchema = new mongoose.Schema({
    name:{
        type:String,
        required: true
    },
    email:{
        type:String,
        required: true
    },
    password:{
        type:String,
        required:true
    },
    // Add these fields for admin password reset
    resetPasswordToken: {
        type: String,
        default: null
    },
    resetPasswordExpires: {
        type: Date,
        default: null
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    loginVerificationCode: {
    type: String
},
loginVerificationExpires: {
    type: Date
}
})

const admin = new mongoose.model("admin", adminSchema,"admins" )

const DatabaseSchema = new mongoose.Schema({
    productName:{
        type:String,
        required: true
    },
    productDescription:{
        type:String,
        required: true
    },
    Price:{
        type:String,
        required:true
    },

    Category:{
        type:String,
        required:true
    },

    Image: {
        type: [String],
        required: true,
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: true // Ensure this field is always set
    },
    isPublic: {
        type: Boolean,
        default: false
    }
})
const Database = new mongoose.model("Database", DatabaseSchema,"AdminData" )

const reviewSchema = new mongoose.Schema({
    productId: {
        type: String,
        required: true
    },
    name: {
        type: String,       
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    comment: {
        type: String,
        required: true
    }
    
})

const ReviewDatabase = new mongoose.model("ReviewDatabase", reviewSchema, "Reviews")


const profileSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user", 
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true  
    },
    DOB: {
        type: String,
        required: true,
    },
    email:{
        type: String,
        required: true
    },
    phone: {
        type: String,
        required: true
    },
    address: {
        street: {
            type: String,
            required: true
        },
        city: {
            type: String,
            required: true
        },
        state: {
            type: String,
            required: true
        },
        zip: {
            type: String,
            required: true
        }
    }
   
})
const profile = new mongoose.model("Profile", profileSchema, "Profiles")

// New model for email verification
const verificationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        refPath: 'userType',
        required: true
    },
    userType: {
        type: String,
        required: true,
        enum: ['user', 'admin']
    },
    token: {
        type: String,
        required: true
    },
    type: {
        type: String,
        required: true,
        enum: ['email', 'login']
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 3600 // Token expires after 1 hour
    }
});


// Add indexes for better query performance
verificationSchema.index({ userId: 1, token: 1 });
verificationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 3600 });
const Verification = new mongoose.model("Verification", verificationSchema, "Verifications");

const paymentSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user",
        required: true
    },
    orderId:{
        type:String,
        required:true
    },
    amount: {
        type: Number,
        required: true
    },
    currency: {
        type: String,
        required: true,
        default: 'SGD'
    },
    paymentMethod: {
        type: String,
        required: true,
        enum: ['credit_card', 'debit_card', 'paypal', 'stripe', 'cash_on_delivery'],
        default: 'credit_card'
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'cancelled', 'refunded'],
        default: 'pending',
        required: true
    },
    transactionId:{
        type:String,
        default:null
    },
    items:[{
        productId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Database",
            required: true
        },
        
        quantity: {
            type: Number,
            required: true,
            min : 1
        },
        price: {
            type: Number,
            required: true,
        }
    }],
    shippingAddress: {
        street: String,
        city: String,
        state: String,
        zip: String
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});
 
paymentSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

const payment = new mongoose.model("Payment", paymentSchema, "Payments");


const orderSchema = new mongoose.Schema({
    orderId: {
        type: String,
        required: true,
        unique: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user",
        required: true
    },
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Database",
        required: true
    },
    productName: {
        type: String,
        required: true
    },
    productImage: {
        type: String
    },
    quantity: {
        type: Number,
        required: true,
        min: 1
    },
    unitPrice: {
        type: Number,
        required: true
    },
    totalAmount: {
        type: Number,
        required: true
    },
    shippingAddress: {
        type: String,
        required: true
    },
    orderStatus: {
        type: String,
        enum: ['confirmed', 'processing', 'shipped', 'delivered', 'cancelled'],
        default: 'confirmed'
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'refunded'],
        default: 'pending'
    },
    orderDate: {
        type: Date,
        default: Date.now
    },
    estimatedDelivery: {
        type: Date
    }
});

const Order = new mongoose.model("Order", orderSchema, "Orders");


export {user, admin, Database, ReviewDatabase, profile, Verification, payment, Order}