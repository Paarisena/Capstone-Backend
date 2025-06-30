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
    required: true
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
})

const admin = new mongoose.model("admin", adminSchema,"admins" )

const profileSchema = new mongoose.Schema({
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

    category:{
        type:String,
        required:true
    },

    Image: {
        type: [String],
        required: true,
    },
})
const Database = new mongoose.model("Database", profileSchema,"AdminData" )

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


export {user, admin, Database, ReviewDatabase}