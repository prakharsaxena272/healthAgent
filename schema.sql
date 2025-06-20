CREATE DATABASE IF NOT EXISTS healthagent;
USE healthagent;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    date DATE NOT NULL,
    items TEXT,
    calories FLOAT,
    protein FLOAT,
    fat FLOAT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS mood_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    date DATE NOT NULL,
    mood VARCHAR(100),
    energy_level INT,
    sleep_quality INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
