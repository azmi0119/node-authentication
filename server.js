require("dotenv").config()
const mongoose = require("mongoose")
const express = require("express")
const userRoute = require("./routes/userRoutes")
const authRoute = require("./routes/authRoute")
const app = express();

app.set('view engine', 'ejs')
app.set('views', './views')

// mongoose.connect("mongodb://localhost:27017/node-authentication");

// Use MongoDB connection URL from .env file or default value
const mongoDBURL = "mongodb://127.0.0.1:27017/node-authentication";

// Connect to MongoDB
mongoose.connect(mongoDBURL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("Connected to MongoDB successfully"))
    .catch((error) => console.error("Failed to connect to MongoDB:", error));

app.use('/api', userRoute)
app.use('/', authRoute)

const port = process.env.SERVER_PORT | 3000;

app.listen(port, ()=> {
    console.log(`Server are running on port ${port}`)
})