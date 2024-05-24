import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const PORT = process.env.PORT || 9002;
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("DB connected"))
.catch(err => console.error("DB connection error:", err));

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

app.post("/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (user) {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                res.status(200).send({ message: "Login Successful", user });
            } else {
                res.status(401).send({ message: "Password didn't match" });
            }
        } else {
            res.status(404).send({ message: "User not registered" });
        }
    } catch (err) {
        res.status(500).send({ message: "Server Error", error: err.message });
    }
});

app.post("/auth/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            res.status(409).send({ message: "User already registered" });
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new User({ name, email, password: hashedPassword });
            await newUser.save();
            res.status(201).send({ message: "Successfully Registered, Please login now." });
        }
    } catch (err) {
        res.status(500).send({ message: "Server Error", error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server started at port ${PORT}`);
});
