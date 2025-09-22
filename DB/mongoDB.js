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

const connecttodb = async() =>{
    try{
        await client.connect();
        console.log("DB Connected Success")
    }catch (err){
        console.log("Error in MongoDB" + err)
    }
}

export{db}
export{localdb}

export default connecttodb