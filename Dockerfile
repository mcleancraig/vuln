# Use the official Node.js runtime as the base image
FROM node:18-alpine

# Set the working directory inside the container
WORKDIR /app

# Set versions
ARG GIT_COMMIT=unknown
ARG GIT_VERSION=unknown

# Set as environment variables
ENV GIT_COMMIT=${GIT_COMMIT}
ENV GIT_VERSION=${GIT_VERSION}

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy the rest of your application code
COPY . .

# Expose the port your app runs on (adjust as needed)
EXPOSE 3000

# Define the command to run your application
CMD ["node", "app-sso.js"]
