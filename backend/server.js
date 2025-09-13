const dotenv = require('dotenv');
dotenv.config();
const { connectDB } = require('./connection.js');
const app = require('./app');

const port = process.env.PORT || 3000;
const mongoURI = process.env.MONGO_URI || "";

console.log("Env test | MONGO_URI:", process.env.MONGO_URI);

// Connect to MongoDB
connectDB(mongoURI);

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Security check: Ensure no sensitive keys are exposed in the codebase
const sensitiveKeysPattern = /API_KEY|SECRET|TOKEN|KEY|OPENAI/i;
const checkSensitiveKeys = (obj, parentKey = '') => {
  for (let key in obj) {
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      checkSensitiveKeys(obj[key], `${parentKey}${key}.`);
    } else if (sensitiveKeysPattern.test(obj[key])) {
      console.warn(`Warning: Sensitive key found in ${parentKey}${key}: ${obj[key]}`);
    }
  }
};

checkSensitiveKeys(process.env);