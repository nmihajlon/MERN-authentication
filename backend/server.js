import express from "express"
import cors from 'cors'
import 'dotenv/config'
import cookieParser from "cookie-parser"
import connectDB from "./config/mongodb.js"

const app = express();
const port = process.env.PORT || 4000;

connectDB();
app.use(express.json())
app.use(cookieParser())
// credentials: true -> za slanje cookie kroz odgovor
app.use(cors({credentials: true}))


app.get('/' );

app.listen(port, () => {
    console.log(`Server started on PORT: ${port}`);
})