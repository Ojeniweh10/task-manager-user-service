
CREATE TABLE IF NOT EXISTS users (
    usertag VARCHAR(20) PRIMARY KEY,  
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,  -- Still needed for task-specific operations
    title VARCHAR(255) NOT NULL,
    description TEXT,
    deadline DATETIME,  -- Store the deadline in DateTime format
    category_id INT,  -- Foreign key reference to categories table
    usertag VARCHAR(6),  -- Foreign key reference to users(usertag)
    status ENUM('Pending', 'In Progress', 'Completed') DEFAULT 'Pending',  -- Enum for task status
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
    FOREIGN KEY (usertag) REFERENCES users(usertag) ON DELETE CASCADE
);

-- Index for retrieving tasks by usertag
CREATE INDEX idx_usertag ON tasks(usertag);
