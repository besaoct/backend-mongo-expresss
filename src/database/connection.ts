import mongoose from "mongoose";
import { config } from "../config";
import createHttpError from "http-errors";

const databaseConnection = async () => {
  try {
    const dbUri = config.databaseUrl as string;
    if (!dbUri) {
      throw createHttpError(500, "MongoDB URI is missing from configuration.");
    }

    // Mongoose connection options
    const options: mongoose.ConnectOptions = {
      autoIndex: config.env==='development'? true : false, // Enable/disable index creation (production: false for performance)
      maxPoolSize: 10, // Maintain up to 10 connections
      serverSelectionTimeoutMS: 5000, // Timeout after 5s if unable to connect
    };

    // Connect to MongoDB
    await mongoose.connect(dbUri, options);

    console.log("✅ MongoDB connected successfully.");

  } catch (err) {
    console.error("Failed to connect to database", err);
    process.exit(1);
  }
};

// Mongoose connection events (for debugging & handling disconnects)
mongoose.connection.on("connected", () => {
  console.log("🟢 Mongoose connected to the database.");
});

mongoose.connection.on("error", (err) => {
  console.error(`❗ Mongoose connection error: ${err.message}`);
});

mongoose.connection.on("disconnected", () => {
  console.log("🔴 Mongoose disconnected.");
});

export default databaseConnection;
