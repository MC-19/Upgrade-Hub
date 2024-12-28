# Walking An Application - Introduction

In this room, you will learn how to manually analyze a web application for security vulnerabilities using only the in-built tools provided by your browser. While automated security tools and scripts are helpful, they often overlook potential vulnerabilities and valuable information.

This room focuses on leveraging the following browser tools:

- **View Source**: Access and review the human-readable source code of a website.
- **Inspector**: Inspect and modify page elements to uncover typically blocked content.
- **Debugger**: Explore and control the execution flow of the page's JavaScript.
- **Network**: Monitor all network requests made by the page.

By mastering these tools, you will gain practical insights into identifying and understanding web application vulnerabilities effectively.

# Website Feature Review - Introduction

As a penetration tester, your primary goal when reviewing a website or web application is to identify features that may be vulnerable and attempt to exploit them to assess their security. These features typically involve interactive components that engage with the user.

Identifying interactive parts of a website can range from recognizing login forms to manually analyzing the website's JavaScript. A simple and effective starting point is to explore the website using your browser, documenting individual pages, features, and a summary of their purpose.

Here’s an example of a site review for the Acme IT Support website:

| **Feature**          | **URL**                  | **Summary**                                                                                     |
|-----------------------|--------------------------|-------------------------------------------------------------------------------------------------|
| **Home Page**         | `/`                      | Overview of Acme IT Support with a company photo of their staff.                               |
| **Latest News**       | `/news`                  | Contains recently published news articles with links including an ID, e.g., `/news/article?id=1`. |
| **News Article**      | `/news/article?id=1`     | Displays individual articles; some are restricted for premium customers.                      |
| **Contact Page**      | `/contact`               | A contact form with name, email, message fields, and a send button.                           |
| **Customers**         | `/customers`             | Redirects to `/customers/login`.                                                              |
| **Customer Login**    | `/customers/login`       | Login form with username and password fields.                                                 |
| **Customer Signup**   | `/customers/signup`      | Signup form with fields for username, email, password, and password confirmation.             |
| **Customer Reset Password** | `/customers/reset`  | Password reset form with an email address input field.                                         |
| **Customer Dashboard** | `/customers`            | Displays the user's tickets and includes a "Create Ticket" button.                            |
| **Create Ticket**     | `/customers/ticket/new`  | Form with a textbox for IT issues and a file upload option to create support tickets.         |
| **Customer Account**  | `/customers/account`     | Allows users to edit their username, email, and password.                                     |
| **Customer Logout**   | `/customers/logout`      | Logs the user out of the customer area.                                                       |

By systematically reviewing and summarizing these features, you can uncover potential vulnerabilities and better understand the web application’s structure.

# Viewing the Page Source - Introduction

The page source is the human-readable code sent by the web server to our browser/client each time a request is made. It includes HTML (HyperText Markup Language), CSS (Cascading Style Sheets), and JavaScript, which together define the structure, appearance, and interactivity of a webpage.

Viewing the page source can provide valuable insights into the web application and potentially reveal sensitive information or vulnerabilities.

---

## How to View the Page Source

1. **Right-click Method**: Right-click anywhere on the webpage and select "View Page Source" from the menu.
2. **Using the URL**: Prefix the URL with `view-source:` (e.g., `view-source:https://www.google.com`).
3. **Browser Menu**: Access the developer tools or "More Tools" section in your browser menu to locate the option.

---

## What to Look for in the Page Source

- **Comments (`<!-- -->`)**: Comments are left by developers for internal use. For example, a comment on the Acme IT Support homepage mentions a temporary page under development. Viewing the page in the comment reveals a flag.
- **Anchor Tags (`<a>`)**: Links to other pages are defined with `<a>` tags and stored in the `href` attribute. For example, on line 31, a link points to the contact page.
- **Hidden Links**: Further down the page, hidden links (e.g., starting with "secr") can lead to private areas potentially containing sensitive information.

---

## External Files and Directory Listings

Websites often include external files such as CSS, JavaScript, or images. These files are typically stored in specific directories. In the Acme IT Support example, a configuration error enables directory listing, exposing all files in the directory. Accessing this directory provides another flag.

**Note**: In real-world scenarios, such directories might store backup files, source code, or other sensitive information, leading to security risks.

---

## Frameworks and Versions

Many websites use frameworks—pre-built codebases that simplify the development process by providing common features like blogs, user management, and form processing.

- **Identifying Frameworks**: Clues about the framework in use (e.g., name and version) are often found in the page source comments.
- **Exploiting Outdated Frameworks**: Knowing the framework and version can help identify vulnerabilities, especially if the site isn't using the latest version.

At the bottom of the Acme IT Support homepage, a comment reveals the framework's version and a link to the framework's website. Viewing this website highlights an outdated version notice, which contains information for another flag.

---

By thoroughly analyzing the page source, you can uncover hidden details and potential vulnerabilities, gaining critical insights into the web application.

# Developer Tools - Introduction

Modern browsers include built-in developer tools designed to help web developers debug applications and provide a deeper look into how a website operates. As a penetration tester, you can use these tools to gain a better understanding of a web application. In this task, we’ll focus on three key features of developer tools: **Inspector**, **Debugger**, and **Network**.

---

## Opening Developer Tools

The method to access developer tools varies by browser. If you're unsure how to open them, refer to your browser's help documentation or the instructions provided in this room.

---

## Inspector

The page source doesn’t always reflect what is currently displayed on a webpage. Dynamic elements, such as those modified by CSS, JavaScript, or user interactions, may change the page content and style. The **Inspector** feature provides a live view of the website as it appears in your browser, allowing you to view, edit, and interact with the page elements in real time.

### Example: Removing a Paywall

On the Acme IT Support website:

1. Navigate to the news section, where you’ll see three articles.
2. The first two articles are readable, but the third is blocked by a floating notice (a paywall) requiring a premium subscription.
3. **Right-click** on the paywall notice and select **Inspect** from the context menu. This opens the developer tools and highlights the relevant HTML element in the **Elements** tab.
4. Locate the `DIV` element with the class `premium-customer-blocker`. 
   - In the **Styles** box, find the property `display: block`.
   - Click on `block` and change it to `none`. This will hide the paywall, revealing the content and a flag.

If the `display` property is missing, you can manually add it by clicking below the last style and typing `display: none;`. You can also experiment with editing other elements on the page, such as modifying text or styling. Note that these changes are only temporary and affect your local browser view; refreshing the page will restore it to its original state.

---

## Key Takeaways

The **Inspector** tool allows you to:

- View and edit HTML and CSS elements in real time.
- Bypass certain webpage restrictions, such as paywalls, for testing purposes.
- Understand how dynamic elements are structured and displayed on the site.

Practicing with these tools will enhance your ability to identify vulnerabilities and gather useful information from web applications.

# Developer Tools - Debugger

The Debugger panel in developer tools is designed for debugging JavaScript. It allows developers to identify and fix issues in their code, but as penetration testers, we can use it to dig deeper into the JavaScript of a web application. In Firefox and Safari, this tool is called **Debugger**, while in Google Chrome, it is known as **Sources**.

---

## Using the Debugger on Acme IT Support

On the Acme IT Support website:

1. Navigate to the **Contact Page**. 
2. When the page loads, you may notice a brief red flash on the screen. We'll use the Debugger to investigate this behavior.

---

## Steps to Debug

### 1. Locate the JavaScript File
- Open the **Debugger** panel in your browser's developer tools.
- On the left-hand side, find the **assets** folder in the list of resources.
- Open the file named `flash.min.js` to view its contents.

### 2. Understanding the JavaScript File
- The file appears **minimized** (formatted into a single line) and **obfuscated** (intentionally made difficult to read).
- Use the **Pretty Print** option (denoted by `{ }`) to reformat the code and make it somewhat more readable.

### 3. Identify Key Code
- Scroll to the bottom of the file to locate the following line:
  ```javascript
  flash['remove']();

# Developer Tools - Network

The **Network** tab in the developer tools allows you to monitor all external requests a webpage makes. This feature is invaluable for tracking resources, debugging, and analyzing how a webpage communicates with external services.

---

## Using the Network Tab

### Monitoring Network Requests
1. Open the **Network** tab in your browser's developer tools.
2. Refresh the page to view all the files and resources requested by the webpage.

### Example: Contact Page
1. Navigate to the **Contact Page**.
2. With the **Network** tab open, fill in the contact form and click the **Send Message** button.
3. Observe a new entry in the **Network** tab. This represents the form being submitted in the background using **AJAX**.

---

## What is AJAX?

AJAX (Asynchronous JavaScript and XML) is a technique used to send and receive data in the background without reloading the webpage. This allows web applications to provide seamless user experiences by dynamically updating content.

---

## Analyzing the Network Request

1. Locate the new entry in the **Network** tab created by the contact form submission.
2. Click on the entry to view details about the request, including:
   - The **URL** the data was sent to.
   - The **method** (e.g., POST).
   - Any data sent along with the request.

3. Inspect the page the data was sent to and reveal the **flag**.

---

## Key Takeaways

The **Network** tab helps you:

- Monitor and analyze all requests made by a webpage.
- Debug and test AJAX requests and responses.
- Identify endpoints and interactions that could reveal sensitive information or vulnerabilities.

By mastering the **Network** tab, you can gain deeper insights into how web applications function and communicate, making it a powerful tool for penetration testing.
