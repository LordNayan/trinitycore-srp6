# Stage 1: Build
FROM node:18 AS build

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (or yarn.lock) into the container
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code into the container
COPY . .

# Run tests (if applicable)
RUN npm test

# Stage 2: Run
FROM node:18

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the application code and node_modules from the build stage
COPY --from=build /usr/src/app /usr/src/app

# Expose the port your app will run on
EXPOSE 3000

# Define the command to run your app
CMD [ "node", "index.js" ]
