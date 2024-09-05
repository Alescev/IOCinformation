import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QUrl
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineSettings, QWebEngineProfile
from PyQt5.QtWebChannel import QWebChannel
from backend import Backend

class MainWindow(QWebEngineView):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP Geolocation App")

        # Set up the backend and web channel
        self.setup_backend()

        # Configure web engine settings
        self.configure_settings()

        # Load the HTML file
        self.load_html()

    def setup_backend(self):
        """Set up the backend and web channel for communication with frontend."""
        self.channel = QWebChannel()
        self.backend = Backend()
        self.channel.registerObject("backend", self.backend)
        self.page().setWebChannel(self.channel)

    def configure_settings(self):
        """Configure QWebEngineSettings for the application."""
        settings = self.settings()
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, True)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, True)
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, True)

        # Disable caching for development purposes
        profile = self.page().profile()
        profile.setHttpCacheType(QWebEngineProfile.NoCache)
        profile.clearHttpCache()

    def load_html(self):
        """Load the main HTML file for the application."""
        current_dir = os.path.dirname(os.path.realpath(__file__))
        index_path = os.path.join(current_dir, 'frontend', 'index.html')

        if os.path.exists(index_path):
            self.load(QUrl.fromLocalFile(index_path))
            self.setGeometry(100, 100, 1000, 800)
        else:
            print(f"Error: {index_path} not found.")
            sys.exit(1)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())