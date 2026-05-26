import csv
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QFrame,
    QGridLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)

from ad_connector import ADConfig, ADConnector
from analyzer import analyze_users


class ADAnalyzerApp(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Active Directory Security Analyzer")
        self.setGeometry(180, 80, 1100, 760)
        self.last_results = None
        self.last_users = None
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        title = QLabel("Active Directory Security Analyzer")
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("Kullanıcı hesaplarını analiz eder, risk seviyelerini belirler ve güvenlik raporu üretir.")
        subtitle.setObjectName("subtitleLabel")
        subtitle.setAlignment(Qt.AlignCenter)

        form_card = QFrame()
        form_card.setObjectName("card")
        form_layout = QVBoxLayout()
        form_layout.setSpacing(10)

        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("Örnek: 192.168.56.10")

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Örnek: administrator@company.local")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Şifre")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.base_dn_input = QLineEdit()
        self.base_dn_input.setPlaceholderText("Örnek: DC=company,DC=local")

        form_layout.addWidget(QLabel("Server"))
        form_layout.addWidget(self.server_input)

        form_layout.addWidget(QLabel("Kullanıcı"))
        form_layout.addWidget(self.user_input)

        form_layout.addWidget(QLabel("Şifre"))
        form_layout.addWidget(self.password_input)

        form_layout.addWidget(QLabel("Base DN"))
        form_layout.addWidget(self.base_dn_input)

        button_row = QHBoxLayout()
        button_row.setSpacing(12)

        self.run_button = QPushButton("Analizi Başlat")
        self.run_button.clicked.connect(self.run_analysis)

        self.export_button = QPushButton("CSV Raporu İndir")
        self.export_button.clicked.connect(self.export_csv)

        self.pdf_button = QPushButton("PDF Raporu İndir")
        self.pdf_button.clicked.connect(self.export_pdf)

        button_row.addWidget(self.run_button)
        button_row.addWidget(self.export_button)
        button_row.addWidget(self.pdf_button)

        form_layout.addLayout(button_row)
        form_card.setLayout(form_layout)

        summary_card = QFrame()
        summary_card.setObjectName("card")
        summary_layout = QGridLayout()
        summary_layout.setSpacing(12)

        self.total_label = self.create_summary_box("Toplam Kullanıcı", "0")
        self.high_label = self.create_summary_box("Yüksek Risk", "0")
        self.medium_label = self.create_summary_box("Orta Risk", "0")
        self.low_label = self.create_summary_box("Düşük Risk", "0")
        self.admin_label = self.create_summary_box("Yönetici Hesap", "0")
        self.inactive_label = self.create_summary_box("İnaktif Hesap", "0")

        summary_layout.addWidget(self.total_label["frame"], 0, 0)
        summary_layout.addWidget(self.high_label["frame"], 0, 1)
        summary_layout.addWidget(self.medium_label["frame"], 0, 2)
        summary_layout.addWidget(self.low_label["frame"], 1, 0)
        summary_layout.addWidget(self.admin_label["frame"], 1, 1)
        summary_layout.addWidget(self.inactive_label["frame"], 1, 2)

        summary_card.setLayout(summary_layout)

        table_card = QFrame()
        table_card.setObjectName("card")
        table_layout = QVBoxLayout()

        table_title = QLabel("Analiz Sonuçları")
        table_title.setObjectName("sectionTitle")

        self.info_label = QLabel("Henüz analiz yapılmadı.")
        self.info_label.setObjectName("infoLabel")

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Username",
            "Full Name",
            "Status",
            "Risk",
            "Admin",
            "Inactive",
            "Recommendation",
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)

        table_layout.addWidget(table_title)
        table_layout.addWidget(self.info_label)
        table_layout.addWidget(self.table)
        table_card.setLayout(table_layout)

        footer = QLabel("Gerçek AD bağlantısı yoksa demo veriler ile test edilebilir.")
        footer.setObjectName("footerLabel")
        footer.setAlignment(Qt.AlignRight)

        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)
        main_layout.addWidget(form_card)
        main_layout.addWidget(summary_card)
        main_layout.addWidget(table_card)
        main_layout.addWidget(footer)

        self.setLayout(main_layout)

    def create_summary_box(self, title, value):
        frame = QFrame()
        frame.setObjectName("summaryBox")

        layout = QVBoxLayout()
        layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("summaryTitle")
        title_label.setAlignment(Qt.AlignCenter)

        value_label = QLabel(str(value))
        value_label.setObjectName("summaryValue")
        value_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        frame.setLayout(layout)

        return {"frame": frame, "title": title_label, "value": value_label}

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #f4f6f8;
                color: #1f2933;
                font-family: Arial;
                font-size: 13px;
            }

            QLabel {
                font-weight: 600;
            }

            #titleLabel {
                font-size: 24px;
                font-weight: 700;
                color: #102a43;
                margin-bottom: 4px;
            }

            #subtitleLabel {
                font-size: 13px;
                font-weight: 400;
                color: #52606d;
                margin-bottom: 8px;
            }

            #sectionTitle {
                font-size: 16px;
                font-weight: 700;
                color: #102a43;
                margin-bottom: 8px;
            }

            #footerLabel {
                font-size: 11px;
                font-weight: 400;
                color: #7b8794;
                margin-top: 4px;
            }

            #infoLabel {
                color: #52606d;
                font-weight: 500;
                margin-bottom: 8px;
            }

            #card {
                background-color: white;
                border: 1px solid #d9e2ec;
                border-radius: 12px;
                padding: 14px;
            }

            #summaryBox {
                background-color: #f8fafc;
                border: 1px solid #d9e2ec;
                border-radius: 10px;
                padding: 12px;
            }

            #summaryTitle {
                font-size: 12px;
                color: #52606d;
                font-weight: 600;
            }

            #summaryValue {
                font-size: 24px;
                color: #102a43;
                font-weight: 700;
            }

            QLineEdit {
                background-color: white;
                border: 1px solid #bcccdc;
                border-radius: 8px;
                padding: 10px;
                min-height: 18px;
            }

            QLineEdit:focus {
                border: 1px solid #2684ff;
            }

            QPushButton {
                background-color: #2684ff;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 16px;
                font-weight: 600;
                min-height: 18px;
            }

            QPushButton:hover {
                background-color: #1f6fe5;
            }

            QPushButton:pressed {
                background-color: #195ec8;
            }

            QTableWidget {
                background-color: #f8fafc;
                border: 1px solid #d9e2ec;
                border-radius: 8px;
                gridline-color: #d9e2ec;
            }

            QHeaderView::section {
                background-color: #e9eef5;
                color: #102a43;
                font-weight: 700;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #d9e2ec;
            }
        """)

    def get_fake_users(self):
        return [
            {
                "sAMAccountName": ["admin"],
                "cn": ["Admin User"],
                "userAccountControl": 512,
                "is_admin": True,
                "last_logon_days_ago": 5,
            },
            {
                "sAMAccountName": ["disabled.user"],
                "cn": ["Disabled User"],
                "userAccountControl": 514,
                "is_admin": False,
                "last_logon_days_ago": 120,
            },
            {
                "sAMAccountName": ["noexpire.user"],
                "cn": ["No Expire User"],
                "userAccountControl": 66048,
                "is_admin": False,
                "last_logon_days_ago": 15,
            },
            {
                "sAMAccountName": ["old.admin"],
                "cn": ["Old Admin User"],
                "userAccountControl": 66048,
                "is_admin": True,
                "last_logon_days_ago": 250,
            },
            {
                "sAMAccountName": ["normal.user"],
                "cn": ["Normal User"],
                "userAccountControl": 512,
                "is_admin": False,
                "last_logon_days_ago": 8,
            },
        ]

    def get_value(self, user, key, default="Bilinmiyor"):
        value = user.get(key, default)
        if isinstance(value, list):
            return value[0] if value else default
        return value

    def update_summary_cards(self, users, results):
        self.total_label["value"].setText(str(len(users)))
        self.high_label["value"].setText(str(len(results["high_risk_users"])))
        self.medium_label["value"].setText(str(len(results["medium_risk_users"])))
        self.low_label["value"].setText(str(len(results["low_risk_users"])))
        self.admin_label["value"].setText(str(len(results["admin_users"])))
        self.inactive_label["value"].setText(str(len(results["inactive_users"])))

    def populate_table(self, users):
        self.table.setRowCount(len(users))

        for row, user in enumerate(users):
            username = str(self.get_value(user, "sAMAccountName"))
            fullname = str(self.get_value(user, "cn"))
            status = str(user.get("status", "UNKNOWN"))
            risk = str(user.get("risk_level", "UNKNOWN"))
            is_admin = "Yes" if user.get("is_admin", False) else "No"
            is_inactive = "Yes" if user.get("is_inactive", False) else "No"
            recommendation = str(user.get("recommendation", ""))

            row_values = [
                username,
                fullname,
                status,
                risk,
                is_admin,
                is_inactive,
                recommendation,
            ]

            for col, value in enumerate(row_values):
                item = QTableWidgetItem(value)

                if col == 3:
                    if risk == "HIGH":
                        item.setBackground(QColor("#ffd6d6"))
                    elif risk == "MEDIUM":
                        item.setBackground(QColor("#fff4cc"))
                    elif risk == "LOW":
                        item.setBackground(QColor("#d9fbe5"))

                self.table.setItem(row, col, item)

    def show_results(self, users, results, source_text):
        self.last_users = users
        self.last_results = results
        self.info_label.setText(source_text)
        self.update_summary_cards(users, results)
        self.populate_table(results["all_users"])

    def run_analysis(self) -> None:
        server = self.server_input.text().strip()
        user = self.user_input.text().strip()
        password = self.password_input.text()
        base_dn = self.base_dn_input.text().strip()

        if not server or not user or not password or not base_dn:
            users = self.get_fake_users()
            results = analyze_users(users)
            self.show_results(users, results, "Demo modu aktif: Fake data kullanıldı.")
            return

        config = ADConfig(
            server=server,
            user=user,
            password=password,
            base_dn=base_dn,
        )

        connector = ADConnector(config)
        is_connected, message = connector.connect()

        if not is_connected:
            users = self.get_fake_users()
            results = analyze_users(users)
            self.show_results(
                users,
                results,
                f"Gerçek AD bağlantısı kurulamadı. Demo modu aktif. Hata: {message}"
            )
            return

        try:
            users = connector.search_users()
            results = analyze_users(users)
            self.show_results(users, results, "Gerçek AD bağlantısı başarılı.")
        except Exception as exc:
            users = self.get_fake_users()
            results = analyze_users(users)
            self.show_results(
                users,
                results,
                f"Analiz sırasında hata oluştu. Demo modu aktif. Hata: {exc}"
            )

    def export_csv(self):
        try:
            if self.last_results is None or self.last_users is None:
                users = self.get_fake_users()
                results = analyze_users(users)
            else:
                users = self.last_users
                results = self.last_results

            with open("rapor.csv", "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)

                writer.writerow([
                    "Kullanıcı Adı",
                    "Ad Soyad",
                    "Durum",
                    "Risk Seviyesi",
                    "Admin Mi",
                    "İnaktif Mi",
                    "Öneri",
                ])

                for user in results["all_users"]:
                    writer.writerow([
                        self.get_value(user, "sAMAccountName"),
                        self.get_value(user, "cn"),
                        user.get("status", "UNKNOWN"),
                        user.get("risk_level", "UNKNOWN"),
                        "EVET" if user.get("is_admin", False) else "HAYIR",
                        "EVET" if user.get("is_inactive", False) else "HAYIR",
                        user.get("recommendation", ""),
                    ])

            QMessageBox.information(self, "Başarılı", "rapor.csv oluşturuldu!")

        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))

    def export_pdf(self):
        try:
            if self.last_results is None or self.last_users is None:
                users = self.get_fake_users()
                results = analyze_users(users)
                source_text = "Demo modu aktif: Fake data kullanıldı."
            else:
                users = self.last_users
                results = self.last_results
                source_text = self.info_label.text()

            filename = "ad_security_report.pdf"
            doc = SimpleDocTemplate(filename, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph("Active Directory Security Analysis Report", styles["Title"]))
            story.append(Spacer(1, 12))
            story.append(Paragraph(f"Rapor Tarihi: {datetime.now().strftime('%d.%m.%Y %H:%M')}", styles["Normal"]))
            story.append(Paragraph(f"Kaynak: {source_text}", styles["Normal"]))
            story.append(Spacer(1, 12))

            summary_data = [
                ["Metric", "Value"],
                ["Toplam Kullanıcı", str(len(users))],
                ["Yüksek Risk", str(len(results["high_risk_users"]))],
                ["Orta Risk", str(len(results["medium_risk_users"]))],
                ["Düşük Risk", str(len(results["low_risk_users"]))],
                ["Yönetici Hesap", str(len(results["admin_users"]))],
                ["İnaktif Hesap", str(len(results["inactive_users"]))],
            ]

            summary_table = Table(summary_data, colWidths=[220, 120])
            summary_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 18))

            story.append(Paragraph("User Details", styles["Heading2"]))
            story.append(Spacer(1, 8))

            details_data = [[
                "Username", "Full Name", "Status", "Risk", "Admin", "Inactive"
            ]]

            for user in results["all_users"]:
                details_data.append([
                    str(self.get_value(user, "sAMAccountName")),
                    str(self.get_value(user, "cn")),
                    str(user.get("status", "UNKNOWN")),
                    str(user.get("risk_level", "UNKNOWN")),
                    "Yes" if user.get("is_admin", False) else "No",
                    "Yes" if user.get("is_inactive", False) else "No",
                ])

            details_table = Table(details_data, repeatRows=1)
            details_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#bfdbfe")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(details_table)
            story.append(Spacer(1, 18))

            story.append(Paragraph("Security Recommendations", styles["Heading2"]))
            story.append(Spacer(1, 8))

            recommendations = []
            for user in results["all_users"]:
                username = str(self.get_value(user, "sAMAccountName"))
                recommendation = str(user.get("recommendation", ""))
                recommendations.append([username, recommendation])

            rec_table_data = [["Username", "Recommendation"]] + recommendations
            rec_table = Table(rec_table_data, colWidths=[160, 320])
            rec_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(rec_table)

            doc.build(story)
            QMessageBox.information(self, "Başarılı", f"{filename} oluşturuldu!")

        except Exception as e:
            QMessageBox.critical(self, "Hata", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ADAnalyzerApp()
    window.show()
    sys.exit(app.exec_())
