import app from "./src/app";
import {config} from "./src/config";
import databaseConnection from './src/database/connection'

const startServer = async() => {
    await databaseConnection();
    const port = config.port || 8000;
    app.listen(port,() => {
        console.log(`✨ Listening on port: ${port}`);
    })
}

startServer();