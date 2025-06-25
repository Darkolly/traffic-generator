# traffic-generator
A desktop application for simulating web traffic to any URL, featuring a user-friendly GUI, customizable request settings, and analytics integration for testing and development purposes.

Features

Easy-to-use GUI: Built with Tkinter for intuitive configuration and monitoring.

Customizable Traffic Generation:

Set the target URL.

Specify the number of visits to simulate.

Adjust delay between requests.

Choose the number of concurrent threads.

User-Agent Randomization: Each request uses a random User-Agent string to mimic real browsers and devices.

Analytics Integration:

Google Analytics 4 (GA4): Send events to your GA4 property for testing analytics tracking.

Matomo: Optionally send tracking data to a Matomo instance.

Real-time Logging: View live logs of request statuses and analytics events in the application.

Start/Stop Controls: Easily start or stop traffic generation at any time.

Cross-platform: Runs on Windows (and other platforms with Python and Tkinter).

Use Cases

Analytics Testing: Verify that your Google Analytics or Matomo setup is correctly tracking visits and events.

Load Simulation: Test how your website handles multiple concurrent requests.

Development & QA: Simulate real user traffic patterns for development, debugging, and quality assurance.
