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

export {user, admin, Database, ReviewDatabase, profile, Verification}