import mongoose from "mongoose";
import dotenv from "dotenv"

dotenv.config();

const db_cluster = process.env.DB_CLUSTER || "localhost:27017"
const db_name = process.env.DB_CLUSTER_NAME
const db_user = process.env.DB_USER|| "";
const db_password = process.env.DB_PASSWORD || "";

const localurl = `mongodb://127.0.0.1:27017/${db_name}`

const cloudurl = `mongodb+srv://${db_user}:${db_password}@${db_cluster}/${db_name}?retryWrites=true&w=majority&appName=Cluster0`

const mongooseconnect = async()=>{
    try{
        console.log('Attempting MongoDB connection...');
        console.log('DB Cluster:', process.env.DB_CLUSTER ? 'Set' : 'Not Set');
        console.log('DB Name:', process.env.DB_CLUSTER_NAME ? 'Set' : 'Not Set');
        
        await mongoose.connect(cloudurl, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        console.log("✅ Mongoose Connection Established Successfully");
    } catch(err){
        console.error("❌ MongoDB Connection Error:");
        console.error("Error name:", err.name);
        console.error("Error message:", err.message);
        console.error("Full error:", err);
        
        // Rethrow the error to be handled by the main error handler
        throw new Error(`MongoDB Connection Failed: ${err.message}`);
    }
}



export default mongooseconnect
