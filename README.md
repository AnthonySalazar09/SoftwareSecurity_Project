# SoftwareSecurity_Project

# Flask API with JWT Authentication, RBAC, Rate Limiting, and Audit Logging

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
  - [Authentication](#authentication)
  - [Suppliers](#suppliers)
  - [Products](#products)
  - [Orders](#orders)
  - [Customers](#customers)
  - [Inventory Restocks](#inventory-restocks)
  - [Roles and Permissions](#roles-and-permissions)
- [Testing with Postman](#testing-with-postman)
- [Security Considerations](#security-considerations)

## Introduction
This project is a Flask-based RESTful API that implements:
- JWT Authentication
- Role-Based Access Control (RBAC)
- Rate Limiting
- Audit Logging

The API manages entities such as Suppliers, Products, Orders, Customers, and Inventory Restocks.

## Features
- **JWT Authentication:** Secure token-based authentication using JSON Web Tokens.
- **Role-Based Access Control:** Users are assigned roles with specific permissions.
- **Rate Limiting:** Prevents abuse by limiting the number of requests per user.
- **Audit Logging:** Records all API requests with details for auditing purposes.
- **RESTful Endpoints:** Provides CRUD operations for all entities.

## Prerequisites
- Python 3.6+
- MySQL Server
- pipenv (recommended) or pip

## Installation
### Clone the Repository
```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
```
Create a Virtual Environment

Using pipenv:

```bash
pipenv shell
```
Or using venv:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```
Install Dependencies

```bash
pip install -r requirements.txt
```
If you don't have a requirements.txt, install the following packages:

```bash
pip install flask flask_sqlalchemy flask_marshmallow flask_cors flask_limiter \
flask_jwt_extended pymysql werkzeug
```

## Configuration
Set Environment Variables

Create a .env file or set the following environment variables:

```bash
JWT_SECRET_KEY=your-secret-key
```
Replace your-secret-key with a secure, random string.

Update Database Configuration

In app.py, ensure the SQLALCHEMY_DATABASE_URI is configured correctly:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@localhost/projectdb'
```
Replace username, password, and projectdb with your MySQL credentials and database name.

## Database Setup
Create the Database

Log into your MySQL server and create the database:

```sql
CREATE DATABASE projectdb;
```
Initialize the Database

The application will automatically create tables and seed initial data when you run it for the first time.

## Running the Application
Run the Flask App

```bash
python app.py
```
The application will start on http://localhost:5000.

API Documentation
# Authentication
Login

Endpoint: POST /login

Request Body:

```json
{
  "username": "your-username",
  "password": "your-password"
}
```
Response:

```json
{
  "access_token": "your-jwt-token"
}
```
Protected Endpoints

Include the JWT token in the Authorization header:

```makefile
Authorization: Bearer your-jwt-token
```
# API Documentation

## Suppliers
### Add Supplier
- **Endpoint:** POST /suppliers
- **Permissions Required:** add_supplier

### Get Suppliers
- **Endpoint:** GET /suppliers
- **Permissions Required:** get_supplier

### Update Supplier
- **Endpoint:** PUT /suppliers/{id}
- **Permissions Required:** update_supplier

### Delete Supplier
- **Endpoint:** DELETE /suppliers/{id}
- **Permissions Required:** delete_supplier

## Products
### Add Product
- **Endpoint:** POST /products
- **Permissions Required:** add_product

### Get Products
- **Endpoint:** GET /products
- **Permissions Required:** get_product

### Update Product
- **Endpoint:** PUT /products/{id}
- **Permissions Required:** update_product

### Delete Product
- **Endpoint:** DELETE /products/{id}
- **Permissions Required:** delete_product

## Orders
### Place Order
- **Endpoint:** POST /orders
- **Permissions Required:** add_order

### Get Orders
- **Endpoint:** GET /orders
- **Permissions Required:** get_order

### Update Order
- **Endpoint:** PUT /orders/{id}
- **Permissions Required:** update_order

### Delete Order
- **Endpoint:** DELETE /orders/{id}
- **Permissions Required:** delete_order

## Customers
### Add Customer
- **Endpoint:** POST /customers
- **Permissions Required:** add_customer

### Get Customers
- **Endpoint:** GET /customers
- **Permissions Required:** get_customer

### Update Customer
- **Endpoint:** PUT /customers/{id}
- **Permissions Required:** update_customer

### Delete Customer
- **Endpoint:** DELETE /customers/{id}
- **Permissions Required:** delete_customer

## Inventory Restocks
### Add Inventory Restock
- **Endpoint:** POST /inventoryrestocks
- **Permissions Required:** add_inventory_restock

### Get Inventory Restocks
- **Endpoint:** GET /inventoryrestocks
- **Permissions Required:** get_inventory_restock

### Update Inventory Restock
- **Endpoint:** PUT /inventoryrestocks/{id}
- **Permissions Required:** update_inventory_restock

### Delete Inventory Restock
- **Endpoint:** DELETE /inventoryrestocks/{id}
- **Permissions Required:** delete_inventory_restock

## Roles and Permissions
- **Admin:** Has all permissions.
- **Manager:** Can perform all actions except delete operations.
- **User:** Can view products and place orders.

## Testing with Postman
- Import the API Endpoints into a new Postman collection.
- Set Up Authentication: Obtain an access_token by logging in.
- Add the token to the Authorization header for protected endpoints.
- Perform CRUD Operations using the sample requests provided in the API documentation.
- Test with different user roles to see access control in action.
- Observe Rate Limiting by exceeding the rate limits to receive a 429 Too Many Requests response.
- Check Audit Logs by querying the audit_log table in the database to see the logged requests.

## Security Considerations
- **Environment Variables:** Do not hardcode sensitive information. Use environment variables for secrets like JWT_SECRET_KEY.
- **HTTPS:** In a production environment, ensure the API is served over HTTPS.
- **Token Expiration:** Tokens expire after one hour for security. Clients should handle token refresh as needed.
