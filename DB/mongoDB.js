import {MongoClient} from "mongodb"
import dotenv from "dotenv"

dotenv.config();

const db_cluster = process.env.DB_CLUSTER || "localhost:27017"
const db_name = process.env.DB_CLUSTER_NAME || "ArtGallery";
const db_user = process.env.DB_USER|| "";
const db_password = process.env.DB_PASSWORD || "";

const localurl = `mongodb://127.0.0.1:27017/${db_name}`

const cloudurl = `mongodb+srv://${db_user}:${db_password}@${db_cluster}/${db_name}?retryWrites=true&w=majority&appName=Cluster0`

const client = new MongoClient(cloudurl)
const localclient = new MongoClient(localurl)

const db = client.db(db_name)
const localdb = localclient.db(db_name)

const connecttodb = async() => {
    try {
        // Log connection attempt
        console.log("MongoDB Connection Attempt...");
        
        // Verify environment variables
        const envVars = {
            DB_CLUSTER: process.env.DB_CLUSTER,
            DB_CLUSTER_NAME: process.env.DB_CLUSTER_NAME,
            DB_USER: process.env.DB_USER,
            DB_PASSWORD: process.env.DB_PASSWORD?.slice(0, 3) + '***'
        };
        console.log("Environment variables:", envVars);
        
        // Test connection
        await client.connect();
        
        // Verify database connection
        await db.command({ ping: 1 });
        
        console.log(`✅ MongoDB Connected Successfully to ${db_name}`);
        return true;
    } catch (err) {
        console.error("❌ MongoDB Connection Error");
        console.error("Error Type:", err.name);
        console.error("Error Message:", err.message);
        
        if (err.name === 'MongoServerError') {
            console.error("Authentication failed. Check credentials.");
        } else if (err.name === 'MongoNetworkError') {
            console.error("Network error. Check connectivity.");
        }
        
        // Rethrow to be handled by Express error handler
        throw err;
    }
}

export{db}
export{localdb}

export default connecttodb