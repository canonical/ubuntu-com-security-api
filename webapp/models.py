from collections import defaultdict
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    JSON,
    String,
    Table,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from sqlalchemy.orm import relationship

Base = declarative_base()

notice_cves = Table(
    "notice_cves",
    Base.metadata,
    Column("notice_id", String, ForeignKey("notice.id")),
    Column("cve_id", String, ForeignKey("cve.id")),
)

notice_releases = Table(
    "notice_releases",
    Base.metadata,
    Column("notice_id", String, ForeignKey("notice.id")),
    Column("release_codename", String, ForeignKey("release.codename")),
)


class CVE(Base):
    __tablename__ = "cve"

    id = Column(String, primary_key=True)
    published = Column(DateTime)
    description = Column(String)
    ubuntu_description = Column(String)
    notes = Column(JSON)
    priority = Column(
        Enum(
            "unknown",
            "negligible",
            "low",
            "medium",
            "high",
            "critical",
            name="priorities",
        )
    )
    cvss3 = Column(Float)
    mitigation = Column(String)
    references = Column(JSON)
    patches = Column(JSON)
    tags = Column(JSON)
    bugs = Column(JSON)
    status = Column(
        Enum("not-in-ubuntu", "active", "rejected", name="cve_statuses")
    )
    statuses = relationship("Status", cascade="all, delete-orphan")
    notices = relationship(
        "Notice", secondary=notice_cves, back_populates="cves"
    )

    @hybrid_method
    def get_filtered_notices(self, show_hidden=False):
        notices = []
        for notice in self.notices:
            if notice.is_hidden and not show_hidden:
                continue

            notices.append(notice)

        return notices

    @hybrid_property
    def packages(self):
        packages = defaultdict(dict)
        for status in self.statuses:
            packages[status.package_name][status.release_codename] = status

        return packages

    @hybrid_property
    def package_statuses(self):
        packages = []
        for package_name in self.packages:
            statuses = []
            for release, status in self.packages[package_name].items():
                statuses.append(
                    {
                        "release_codename": status.release_codename,
                        "status": status.status,
                        "description": status.description,
                        "component": status.component,
                        "pocket": status.pocket,
                    }
                )

            pkg = {
                "name": package_name,
                "source": f"https://ubuntu.com/security/cve?"
                f"package={package_name}",
                "ubuntu": f"https://packages.ubuntu.com/search?"
                f"suite=all&section=all&arch=any&"
                f"searchon=sourcenames&keywords={package_name}",
                "debian": f"https://tracker.debian.org/pkg/{package_name}",
                "statuses": statuses,
            }
            packages.append(pkg)

        return packages

    @hybrid_property
    def notices_ids(self):
        return [notice.id for notice in self.notices]


class Notice(Base):
    __tablename__ = "notice"

    id = Column(String, primary_key=True)
    title = Column(String)
    published = Column(DateTime)
    summary = Column(String)
    details = Column(String)
    instructions = Column(String)
    release_packages = Column(JSON)
    cves = relationship("CVE", secondary=notice_cves, back_populates="notices")
    references = Column(JSON)
    is_hidden = Column(Boolean)
    releases = relationship(
        "Release",
        secondary=notice_releases,
        order_by="desc(Release.release_date)",
        back_populates="notices",
    )

    @hybrid_property
    def cves_ids(self):
        return [cve.id for cve in self.cves]

    @hybrid_property
    def notice_type(self):
        if "USN-" in self.id.upper():
            return "USN"
        if "LSN-" in self.id.upper():
            return "LSN"

        return ""

    @hybrid_property
    def package_list(self):
        if not self.release_packages:
            return []

        package_list = []
        for codename, packages in self.release_packages.items():
            for package in packages:
                package_list.append(package["name"])

        return set(sorted(package_list))

    @hybrid_property
    def related_notices(self):
        related_notices_ids = [self.id]
        related_notices = []
        for cve in self.cves:
            for notice in cve.notices:
                if notice.id not in related_notices_ids:
                    related_notices.append(
                        {
                            "id": notice.id,
                            "package_list": ", ".join(notice.package_list),
                        }
                    )
                    related_notices_ids.append(notice.id)

        return related_notices


class Release(Base):
    __tablename__ = "release"

    codename = Column(String, primary_key=True)
    name = Column(String, unique=True)
    version = Column(String, unique=True)
    lts = Column(Boolean)
    development = Column(Boolean)
    release_date = Column(DateTime)
    esm_expires = Column(DateTime)
    support_expires = Column(DateTime)
    statuses = relationship("Status", cascade="all, delete-orphan")
    notices = relationship(
        "Notice", secondary=notice_releases, back_populates="releases"
    )

    @hybrid_property
    def support_tag(self):
        now = datetime.now()

        if self.lts and self.support_expires > now:
            return "LTS"
        elif self.lts and self.esm_expires > now:
            return "ESM"

        return ""


class Status(Base):
    __tablename__ = "status"

    active_statuses = [
        "released",
        "needed",
        "deferred",
        "needs-triage",
        "pending",
    ]

    cve_id = Column(String, ForeignKey("cve.id"), primary_key=True)
    package_name = Column(String, ForeignKey("package.name"), primary_key=True)
    release_codename = Column(
        String, ForeignKey("release.codename"), primary_key=True
    )
    status = Column(
        Enum(
            "released",
            "DNE",
            "needed",
            "not-affected",
            "deferred",
            "needs-triage",
            "ignored",
            "pending",
            name="statuses",
        )
    )
    description = Column(String)
    component = Column(
        Enum("main", "universe", name="components"),
    )
    pocket = Column(
        Enum("security", "updates", "esm-infra", "esm-apps", name="pockets"),
    )

    cve = relationship("CVE", back_populates="statuses")
    package = relationship("Package", back_populates="statuses")
    release = relationship("Release", back_populates="statuses")


class Package(Base):
    __tablename__ = "package"

    name = Column(String, primary_key=True)
    source = Column(String)
    launchpad = Column(String)
    ubuntu = Column(String)
    debian = Column(String)
    statuses = relationship("Status", cascade="all, delete-orphan")
