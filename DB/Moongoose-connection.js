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
    await mongoose.connect(localurl);
    console.log("Mongoose Connection Established")
} catch(err){
    console.log("Mongoose connection error" +err)
}
}



export default mongooseconnect
