# Database Setup Guide

This project uses **SQLite** with Entity Framework Core. You have two options to set up the database:

## Option 1: Automatic Database Creation (Current Setup)

The application automatically creates the database when you run it. The database file `ApplicationSecurity.db` will be created in the project root directory.

**Steps:**
1. Simply run the application:
   ```bash
   dotnet run
   ```
2. The database will be created automatically on first run.

**Note:** This method uses `EnsureCreated()` which is fine for development but not recommended for production.

---

## Option 2: Using EF Core Migrations (Recommended for Production)

For better control and versioning, use Entity Framework migrations:

### Step 1: Install EF Core Tools (if not already installed)

```bash
dotnet tool install --global dotnet-ef
```

Or update if already installed:
```bash
dotnet tool update --global dotnet-ef
```

### Step 2: Create Initial Migration

Navigate to the project directory:
```bash
cd Application_Security_ASSGN2
```

Create the migration:
```bash
dotnet ef migrations add InitialCreate
```

This creates a `Migrations` folder with migration files.

### Step 3: Apply Migration to Create Database

Apply the migration to create/update the database:
```bash
dotnet ef database update
```

This will create the `ApplicationSecurity.db` file in your project directory.

### Step 4: Run the Application

```bash
dotnet run
```

---

## Updating Database Schema (After Model Changes)

If you modify any models (Member, AuditLog, etc.), follow these steps:

1. **Create a new migration:**
   ```bash
   dotnet ef migrations add MigrationName
   ```
   Example: `dotnet ef migrations add AddNewFieldToMember`

2. **Apply the migration:**
   ```bash
   dotnet ef database update
   ```

---

## Database File Location

The SQLite database file (`ApplicationSecurity.db`) will be created in:
```
Application_Security_ASSGN2\ApplicationSecurity.db
```

---

## Troubleshooting

### If migrations fail:
1. Delete the `Migrations` folder (if exists)
2. Delete `ApplicationSecurity.db` (if exists)
3. Run `dotnet ef migrations add InitialCreate` again
4. Run `dotnet ef database update`

### If you want to reset the database:
```bash
dotnet ef database drop
dotnet ef database update
```

---

## Quick Start (Recommended)

For the quickest setup, just run:
```bash
dotnet run
```

The database will be created automatically on first run!
