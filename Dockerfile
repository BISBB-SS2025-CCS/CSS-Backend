# Use an official Node.js runtime as a parent image
FROM node:18-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to install dependencies
# A wildcard is used to ensure both package.json and package-lock.json are copied
COPY package*.json ./

# Install app dependencies
# Use npm ci for clean installs in production environments
RUN npm ci

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Define the command to run the app
CMD ["node", "server.js"]