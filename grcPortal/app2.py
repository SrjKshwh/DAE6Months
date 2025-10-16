@app.route("/monitoring", methods=["GET"])
@login_required
def monitoring():
    """
    Display SOC monitoring dashboard with real-time system metrics.

    Shows system performance metrics, security events, and active incidents
    for continuous security monitoring and operational visibility.
    """
    user = current_user()
    db = get_session()

    try:
        import psutil
        import platform

        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()

        # Get active incidents
        active_incidents = db.query(Incident).filter(
            Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])
        ).order_by(Incident.reported_at.desc()).limit(10).all()

        # Get recent security events (simulated for demo)
        security_events = [
            "INFO: User login successful - admin",
            "WARNING: Multiple failed login attempts detected",
            "INFO: Security policy updated",
            "INFO: System backup completed successfully"
        ]

        # Get top processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'][:30],  # Truncate long names
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': proc.info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by CPU usage and take top 10
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        processes = processes[:10]

        close_session(db)

        return render_template("monitoring.html",
                             cpu_percent=cpu_percent,
                             memory=memory,
                             disk=disk,
                             network=network,
                             active_incidents=active_incidents,
                             security_events=security_events,
                             processes=processes)

    except ImportError:
        flash("System monitoring requires 'psutil' library. Please install it.", "warning")
        close_session(db)
        return redirect(url_for('admin_dashboard'))


@app.route("/monitoring_setup", methods=["GET", "POST"])
@login_required
def monitoring_setup():
    """
    Configure security monitoring settings and thresholds.

    Allows administrators to set up monitoring configurations,
    alert thresholds, and system monitoring parameters.
    """
    user = current_user()
    db = get_session()

    if request.method == "POST":
        try:
            # Create monitoring configuration
            monitoring_name = request.form.get('monitoring_name')
            retention_period = int(request.form.get('retention_period', 90))

            # System metrics
            system_metrics = request.form.getlist('system_metrics')

            # Log sources
            log_sources = request.form.getlist('log_sources')

            # Alert thresholds
            cpu_threshold = float(request.form.get('cpu_threshold', 90))
            memory_threshold = float(request.form.get('memory_threshold', 85))
            disk_threshold = float(request.form.get('disk_threshold', 95))
            network_threshold = float(request.form.get('network_threshold', 1000))

            # Create monitoring configuration
            config = MonitoringConfiguration(
                name=monitoring_name,
                retention_period_days=retention_period,
                cpu_enabled='cpu' in system_metrics,
                memory_enabled='memory' in system_metrics,
                disk_enabled='disk' in system_metrics,
                network_enabled='network' in system_metrics,
                system_logs_enabled='system_logs' in log_sources,
                application_logs_enabled='application_logs' in log_sources,
                security_events_enabled='security_events' in log_sources,
                cpu_threshold=cpu_threshold,
                memory_threshold=memory_threshold,
                disk_threshold=disk_threshold,
                network_threshold=network_threshold,
                creator_id=user.id
            )

            db.add(config)
            db.commit()

            log_audit_event(user, "MONITORING_CONFIG_CREATED", "MONITORING",
                          f"Created monitoring configuration: {monitoring_name}", "/monitoring_setup", True)

            flash(f"Monitoring configuration '{monitoring_name}' created successfully!", "success")

        except Exception as e:
            db.rollback()
            flash(f"Error creating monitoring configuration: {str(e)}", "error")

        return redirect(url_for('monitoring_setup'))

    # GET request - show monitoring setup form
    try:
        import psutil

        # Get current system metrics for display
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()

        # Get existing configurations
        configurations = db.query(MonitoringConfiguration).order_by(
            MonitoringConfiguration.created_at.desc()
        ).all()

        # Get recent alerts (simulated)
        alerts = []

        # Get recent security events
        security_events = [
            "INFO: System monitoring initialized",
            "INFO: CPU usage within normal parameters",
            "INFO: Memory usage stable"
        ]

        # Get processes for monitoring
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'][:25],
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': proc.info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        processes = processes[:8]

        close_session(db)

        return render_template("monitoring_setup.html",
                             cpu_percent=cpu_percent,
                             memory=memory,
                             disk=disk,
                             network=network,
                             configurations=configurations,
                             alerts=alerts,
                             security_events=security_events,
                             processes=processes)

    except ImportError:
        flash("System monitoring requires 'psutil' library. Please install it.", "warning")
        close_session(db)
        return redirect(url_for('admin_dashboard'))


@app.route("/admin/retention_settings", methods=["GET", "POST"])
@login_required
@admin_required
def admin_retention_settings():
    """
    Manage data retention settings and archive configurations.

    Allows administrators to configure retention periods, enable/disable
    archiving, and manage automatic data lifecycle processes.
    """
    user = current_user()
    db = get_session()

    if request.method == "POST":
        action = request.form.get('action')

        if action == "update_retention":
            try:
                table_name = request.form.get('table_name')
                retention_days = int(request.form.get('retention_days'))
                archive_enabled = request.form.get('enabled') == 'true'
                auto_purge = request.form.get('auto_purge') == 'true'

                # Update retention configuration
                config = db.query(RetentionConfig).filter_by(table_name=table_name).first()
                if config:
                    config.retention_days = retention_days
                    config.archive_enabled = archive_enabled
                    config.auto_purge = auto_purge
                    db.commit()

                    log_audit_event(user, "RETENTION_CONFIG_UPDATED", "ADMIN",
                                  f"Updated retention config for {table_name}", "/admin/retention_settings", True)

                    flash(f"Retention settings for {table_name} updated successfully!", "success")
                else:
                    flash(f"Retention configuration for {table_name} not found.", "error")

            except Exception as e:
                db.rollback()
                flash(f"Error updating retention settings: {str(e)}", "error")

        elif action == "manual_archive":
            try:
                # Trigger manual archiving process
                archived_count = perform_manual_archive(db)

                log_audit_event(user, "MANUAL_ARCHIVE_EXECUTED", "ADMIN",
                              f"Manual archive completed: {archived_count} records archived", "/admin/retention_settings", True)

                flash(f"Manual archive completed successfully! {archived_count} records archived.", "success")

            except Exception as e:
                db.rollback()
                flash(f"Error during manual archive: {str(e)}", "error")

        return redirect(url_for('admin_retention_settings'))

    # GET request - show retention settings
    retention_configs = db.query(RetentionConfig).all()

    # Get archive statistics
    archive_stats = {
        'risk_archive': db.query(RiskArchive).count(),
        'audit_archive': db.query(AuditArchive).count(),
        'incident_archive': db.query(IncidentArchive).count()
    }

    close_session(db)

    return render_template("admin_retention_settings.html",
                         retention_configs=retention_configs,
                         archive_stats=archive_stats)


def perform_manual_archive(db):
    """
    Perform manual archiving of records based on retention policies.

    Args:
        db: Database session

    Returns:
        int: Number of records archived
    """
    total_archived = 0
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)  # Archive records older than 30 days for demo

    try:
        # Archive risks
        old_risks = db.query(Risk).filter(Risk.created_at < cutoff_date).all()
        for risk in old_risks:
            archive_record = RiskArchive(
                original_id=risk.id,
                title=risk.title,
                description=risk.description,
                impact=risk.impact,
                likelihood=risk.likelihood,
                risk_score=risk.risk_score,
                status=risk.status,
                owner_id=risk.owner_id,
                created_at=risk.created_at,
                archived_at=datetime.now(timezone.utc)
            )
            db.add(archive_record)
            db.delete(risk)
            total_archived += 1

        # Archive audit logs
        old_audits = db.query(AuditLog).filter(AuditLog.timestamp < cutoff_date).all()
        for audit in old_audits:
            archive_record = AuditArchive(
                original_id=audit.id,
                user_id=audit.user_id,
                action=audit.action,
                resource_type=audit.resource_type,
                resource_id=audit.resource_id,
                details=audit.details,
                ip_address=audit.ip_address,
                user_agent=audit.user_agent,
                timestamp=audit.timestamp,
                archived_at=datetime.now(timezone.utc)
            )
            db.add(archive_record)
            db.delete(audit)
            total_archived += 1

        # Archive incidents
        old_incidents = db.query(Incident).filter(Incident.reported_at < cutoff_date).all()
        for incident in old_incidents:
            archive_record = IncidentArchive(
                original_id=incident.id,
                title=incident.title,
                description=incident.description,
                severity=incident.severity,
                status=incident.status,
                reported_by=incident.reported_by,
                assigned_to=incident.assigned_to,
                reported_at=incident.reported_at,
                archived_at=datetime.now(timezone.utc)
            )
            db.add(archive_record)
            db.delete(incident)
            total_archived += 1

        db.commit()

    except Exception as e:
        db.rollback()
        raise e

    return total_archived


@app.route("/compliance_status_report", methods=["GET", "POST"])
@login_required
def compliance_status_report():
        """
        Generate comprehensive compliance status report suitable for management.

        Produces professional compliance status report including:
        - Executive summary with key findings
        - Compliance status across all frameworks
        - Risk-based compliance analysis
        - Recommendations and action items
        - Professional formatting for management distribution

        Supports multiple output formats and stakeholder-specific views.
        """
        user = current_user()
        db = get_session()

        if request.method == "POST":
            # Generate compliance status report
            report_format = request.form.get("format", "html")
            report_period = request.form.get("period", "current")
            include_recommendations = request.form.get("include_recommendations", "true") == "true"

            # Collect compliance data
            compliance_data = generate_compliance_status_data(db, report_period)

            if report_format == "pdf":
                # Generate PDF report
                report_content = generate_compliance_pdf_report(compliance_data, include_recommendations)
                report_filename = f"compliance_status_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

                # Save to reports directory
                report_path = os.path.join("reports", report_filename)
                with open(report_path, "wb") as f:
                    f.write(report_content)

                # Log report generation
                log_audit_event(user, "COMPLIANCE_REPORT_GENERATED", "COMPLIANCE",
                              f"Generated compliance status report: {report_filename}", "/compliance_status_report", True)

                flash(f"Compliance status report generated: {report_filename}", "success")
                return send_from_directory("reports", report_filename, as_attachment=True)

            else:
                # Generate HTML report
                report_data = generate_compliance_html_report(compliance_data, include_recommendations)

                # Log report generation
                log_audit_event(user, "COMPLIANCE_REPORT_GENERATED", "COMPLIANCE",
                              "Generated HTML compliance status report", "/compliance_status_report", True)

                return render_template("compliance_status_report.html", **report_data)

        # GET request - show report generation form
        # Get available compliance frameworks
        frameworks = db.query(ComplianceFramework).distinct().all()
        framework_list = [f.value for f in ComplianceFramework]

        close_session(db)
        return render_template("compliance_status_report_form.html",
                             frameworks=framework_list,
                             current_date=datetime.now().strftime('%Y-%m-%d'))


def generate_compliance_status_data(db, period="current"):
    """
    Generate comprehensive compliance status data for reporting.

    Args:
        db: Database session
        period: Report period ("current", "quarterly", "annual")

    Returns:
        dict: Structured compliance data for report generation
    """
    # Get compliance records
    compliance_records = db.query(Compliance).all()

    # Get risk-based compliance mapping
    risk_compliance_mappings = db.query(RiskComplianceMapping).all()

    # Calculate framework compliance scores
    framework_scores = {}
    for framework in ComplianceFramework:
        framework_compliance = [c for c in compliance_records if c.framework == framework.value]
        if framework_compliance:
            avg_score = sum(c.get_effective_score() for c in framework_compliance) / len(framework_compliance)
            compliant_count = sum(1 for c in framework_compliance if c.get_effective_score() >= 80)
            total_count = len(framework_compliance)
            framework_scores[framework.value] = {
                "average_score": avg_score,
                "compliant_controls": compliant_count,
                "total_controls": total_count,
                "compliance_percentage": (compliant_count / total_count) * 100 if total_count > 0 else 0
            }

    # Identify critical compliance gaps
    critical_gaps = []
    for compliance in compliance_records:
        if compliance.get_effective_score() < 60:  # Critical threshold
            critical_gaps.append({
                "framework": compliance.framework,
                "control": compliance.control,
                "current_score": compliance.get_effective_score(),
                "risk_level": "Critical" if compliance.get_effective_score() < 40 else "High"
            })

    # Risk-based compliance analysis
    risk_compliance_analysis = []
    for mapping in risk_compliance_mappings:
        risk_compliance_analysis.append({
            "risk_id": mapping.risk_id,
            "requirement": mapping.requirement.requirement_id if mapping.requirement else "Unknown",
            "framework": mapping.requirement.framework.value if mapping.requirement else "Unknown",
            "impact_level": mapping.impact_level,
            "compliance_status": "Compliant" if mapping.requirement and any(
                c.framework == mapping.requirement.framework.value and c.control == mapping.requirement.title and c.get_effective_score() >= 80
                for c in compliance_records
            ) else "Non-Compliant"
        })

    return {
        "framework_scores": framework_scores,
        "critical_gaps": critical_gaps,
        "risk_compliance_analysis": risk_compliance_analysis,
        "total_compliance_records": len(compliance_records),
        "overall_compliance_score": sum(f["average_score"] for f in framework_scores.values()) / len(framework_scores) if framework_scores else 0,
        "generated_at": datetime.now(),
        "report_period": period
    }


def generate_compliance_html_report(compliance_data, include_recommendations=True):
    """
    Generate HTML formatted compliance status report.

    Args:
        compliance_data: Structured compliance data
        include_recommendations: Whether to include recommendations section

    Returns:
        dict: Template variables for HTML report
    """
    # Calculate key metrics
    overall_score = compliance_data["overall_compliance_score"]
    critical_gaps_count = len([g for g in compliance_data["critical_gaps"] if g["risk_level"] == "Critical"])
    high_gaps_count = len([g for g in compliance_data["critical_gaps"] if g["risk_level"] == "High"])

    # Generate executive summary
    executive_summary = {
        "overall_compliance_score": overall_score,
        "compliance_rating": "Excellent" if overall_score >= 90 else "Good" if overall_score >= 80 else "Needs Improvement" if overall_score >= 70 else "Critical Attention Required",
        "critical_gaps": critical_gaps_count,
        "high_priority_gaps": high_gaps_count,
        "frameworks_assessed": len(compliance_data["framework_scores"]),
        "total_controls": sum(f["total_controls"] for f in compliance_data["framework_scores"].values())
    }

    # Generate recommendations if requested
    recommendations = []
    if include_recommendations:
        if overall_score < 80:
            recommendations.append({
                "priority": "High",
                "category": "Immediate Action Required",
                "description": "Overall compliance score below acceptable threshold",
                "action_items": [
                    "Conduct immediate gap analysis for critical controls",
                    "Implement remediation plans for high-risk compliance gaps",
                    "Schedule urgent management review meeting"
                ]
            })

        if critical_gaps_count > 0:
            recommendations.append({
                "priority": "Critical",
                "category": "Critical Compliance Gaps",
                "description": f"Address {critical_gaps_count} critical compliance gaps immediately",
                "action_items": [
                    "Prioritize remediation of critical control failures",
                    "Allocate additional resources for compliance remediation",
                    "Establish accountability for critical gap resolution"
                ]
            })

        if len(compliance_data["framework_scores"]) < 3:
            recommendations.append({
                "priority": "Medium",
                "category": "Framework Coverage",
                "description": "Limited compliance framework coverage detected",
                "action_items": [
                    "Expand compliance monitoring to additional frameworks",
                    "Conduct framework gap analysis",
                    "Implement additional compliance controls as needed"
                ]
            })

    return {
        "executive_summary": executive_summary,
        "framework_scores": compliance_data["framework_scores"],
        "critical_gaps": compliance_data["critical_gaps"],
        "risk_compliance_analysis": compliance_data["risk_compliance_analysis"],
        "recommendations": recommendations,
        "generated_at": compliance_data["generated_at"],
        "report_period": compliance_data["report_period"],
        "include_recommendations": include_recommendations
    }


def generate_compliance_pdf_report(compliance_data, include_recommendations=True):
    """
    Generate PDF formatted compliance status report.

    Args:
        compliance_data: Structured compliance data
        include_recommendations: Whether to include recommendations section

    Returns:
        bytes: PDF report content
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from io import BytesIO

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph("Compliance Status Report", title_style))
        story.append(Spacer(1, 12))

        # Generation info
        story.append(Paragraph(f"Generated: {compliance_data['generated_at'].strftime('%B %d, %Y at %I:%M %p')}", styles['Normal']))
        story.append(Paragraph(f"Report Period: {compliance_data['report_period'].title()}", styles['Normal']))
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Spacer(1, 12))

        overall_score = compliance_data['overall_compliance_score']
        critical_gaps = len([g for g in compliance_data['critical_gaps'] if g['risk_level'] == 'Critical'])
        high_gaps = len([g for g in compliance_data['critical_gaps'] if g['risk_level'] == 'High'])

        summary_data = [
            ["Overall Compliance Score", f"{overall_score:.1f}%"],
            ["Compliance Rating", "Excellent" if overall_score >= 90 else "Good" if overall_score >= 80 else "Needs Improvement" if overall_score >= 70 else "Critical Attention Required"],
            ["Critical Gaps", str(critical_gaps)],
            ["High Priority Gaps", str(high_gaps)],
            ["Frameworks Assessed", str(len(compliance_data['framework_scores']))],
            ["Total Controls", str(sum(f['total_controls'] for f in compliance_data['framework_scores'].values()))]
        ]

        summary_table = Table(summary_data, colWidths=[200, 200])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Framework Compliance Scores
        story.append(Paragraph("Framework Compliance Scores", styles['Heading2']))
        story.append(Spacer(1, 12))

        framework_data = [["Framework", "Average Score", "Compliant Controls", "Total Controls", "Compliance %"]]
        for framework, scores in compliance_data["framework_scores"].items():
            framework_data.append([
                framework,
                f"{scores['average_score']:.1f}%",
                str(scores['compliant_controls']),
                str(scores['total_controls']),
                f"{scores['compliance_percentage']:.1f}%"
            ])

        framework_table = Table(framework_data, colWidths=[100, 80, 100, 80, 80])
        framework_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(framework_table)
        story.append(Spacer(1, 20))

        # Critical Compliance Gaps
        if compliance_data['critical_gaps']:
            story.append(Paragraph("Critical Compliance Gaps", styles['Heading2']))
            story.append(Spacer(1, 12))

            gap_data = [["Framework", "Control", "Current Score", "Risk Level"]]
            for gap in compliance_data['critical_gaps']:
                gap_data.append([
                    gap['framework'],
                    gap['control'][:30] + "..." if len(gap['control']) > 30 else gap['control'],
                    f"{gap['current_score']:.1f}%",
                    gap['risk_level']
                ])

            gap_table = Table(gap_data, colWidths=[80, 150, 80, 80])
            gap_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(gap_table)
            story.append(Spacer(1, 20))

        # Recommendations
        if include_recommendations:
            story.append(Paragraph("Recommendations & Action Items", styles['Heading2']))
            story.append(Spacer(1, 12))

            recommendations = []
            if overall_score < 80:
                recommendations.append("• Immediate action required to improve overall compliance score")
            if critical_gaps > 0:
                recommendations.append(f"• Address {critical_gaps} critical compliance gaps immediately")
            if len(compliance_data['framework_scores']) < 3:
                recommendations.append("• Expand compliance monitoring to additional frameworks")

            if recommendations:
                for rec in recommendations:
                    story.append(Paragraph(rec, styles['Normal']))
                    story.append(Spacer(1, 6))
            else:
                story.append(Paragraph("• No critical recommendations at this time", styles['Normal']))

        # Build PDF
        doc.build(story)
        pdf_content = buffer.getvalue()
        buffer.close()
        return pdf_content

    except ImportError:
        # Fallback to text-based report if ReportLab not available
        report_content = f"""COMPLIANCE STATUS REPORT
Generated: {compliance_data['generated_at']}

EXECUTIVE SUMMARY
=================
Overall Compliance Score: {compliance_data['overall_compliance_score']:.1f}%
Critical Gaps: {len([g for g in compliance_data['critical_gaps'] if g['risk_level'] == 'Critical'])}
High Priority Gaps: {len([g for g in compliance_data['critical_gaps'] if g['risk_level'] == 'High'])}

FRAMEWORK COMPLIANCE SCORES
===========================
"""

        for framework, scores in compliance_data["framework_scores"].items():
            report_content += f"""
{framework}:
  Average Score: {scores['average_score']:.1f}%
  Compliant Controls: {scores['compliant_controls']}/{scores['total_controls']}
  Compliance Percentage: {scores['compliance_percentage']:.1f}%
"""

        if include_recommendations:
            report_content += "\n\nRECOMMENDATIONS\n===============\n"
            if compliance_data['overall_compliance_score'] < 80:
                report_content += "- Immediate action required to improve overall compliance score\n"
            if len(compliance_data['critical_gaps']) > 0:
                report_content += f"- Address {len(compliance_data['critical_gaps'])} critical compliance gaps\n"

        return report_content.encode('utf-8')


@app.route("/ethical_decision_support", methods=["GET", "POST"])
@login_required
def ethical_decision_support():
    """
    Ethical decision support tool for compliance scenarios.

    Provides structured ethical analysis framework with stakeholder impact
    assessment, alternative evaluation, and decision documentation.
    """
    user = current_user()
    db = get_session()

    if request.method == "POST":
        action = request.form.get('action')

        if action == "create_decision":
            try:
                # Create ethical decision record
                title = request.form.get('title')
                description = request.form.get('description')
                scenario_type = request.form.get('scenario_type')

                # Ethical analysis
                principles = request.form.getlist('ethical_principles')
                stakeholder_analysis = request.form.get('stakeholder_analysis')
                alternatives = request.form.get('alternatives')

                # Decision details
                decision = request.form.get('decision')
                rationale = request.form.get('rationale')
                ethical_risk = request.form.get('ethical_risk_level', 'medium')

                # Implementation
                implementation_plan = request.form.get('implementation_plan')
                monitoring = request.form.get('monitoring_requirements')

                ethical_decision = EthicalDecision(
                    title=title,
                    description=description,
                    scenario_type=scenario_type,
                    ethical_principles_applied=json.dumps(principles),
                    stakeholder_impact_analysis=stakeholder_analysis,
                    alternative_options=alternatives,
                    decision_made=decision,
                    rationale=rationale,
                    ethical_risk_level=ethical_risk,
                    implementation_plan=implementation_plan,
                    monitoring_requirements=monitoring,
                    decided_by=user.id
                )

                db.add(ethical_decision)
                db.commit()

                log_audit_event(user, "ETHICAL_DECISION_CREATED", "ETHICS",
                              f"Created ethical decision: {title}", "/ethical_decision_support", True)

                flash(f"Ethical decision '{title}' documented successfully!", "success")

            except Exception as e:
                db.rollback()
                flash(f"Error creating ethical decision: {str(e)}", "error")

        elif action == "update_decision":
            try:
                decision_id = int(request.form.get('decision_id'))
                ethical_decision = db.query(EthicalDecision).filter_by(id=decision_id).first()

                if ethical_decision:
                    # Update decision details
                    ethical_decision.title = request.form.get('title')
                    ethical_decision.description = request.form.get('description')
                    ethical_decision.scenario_type = request.form.get('scenario_type')
                    ethical_decision.decision_made = request.form.get('decision')
                    ethical_decision.rationale = request.form.get('rationale')
                    ethical_decision.ethical_risk_level = request.form.get('ethical_risk_level', 'medium')
                    ethical_decision.implementation_plan = request.form.get('implementation_plan')
                    ethical_decision.monitoring_requirements = request.form.get('monitoring_requirements')

                    db.commit()

                    log_audit_event(user, "ETHICAL_DECISION_UPDATED", "ETHICS",
                                  f"Updated ethical decision: {ethical_decision.title}", "/ethical_decision_support", True)

                    flash(f"Ethical decision updated successfully!", "success")
                else:
                    flash("Ethical decision not found.", "error")

            except Exception as e:
                db.rollback()
                flash(f"Error updating ethical decision: {str(e)}", "error")

        return redirect(url_for('ethical_decision_support'))

    # GET request - show ethical decision support interface
    try:
        # Get existing ethical decisions
        ethical_decisions = db.query(EthicalDecision).order_by(
            EthicalDecision.created_at.desc()
        ).all()

        # Get ethical scenario templates
        scenario_templates = {
            "data_privacy": {
                "title": "Data Privacy vs Business Need",
                "description": "Balancing data collection needs with individual privacy rights",
                "principles": ["Privacy", "Transparency", "Data Minimization"]
            },
            "security_tradeoff": {
                "title": "Security vs User Experience",
                "description": "Implementing security measures that may impact usability",
                "principles": ["Security", "Usability", "Risk Mitigation"]
            },
            "vendor_risk": {
                "title": "Cost vs Ethical Vendor Practices",
                "description": "Selecting vendors based on cost vs ethical considerations",
                "principles": ["Fair Labor", "Environmental Responsibility", "Corporate Ethics"]
            },
            "employee_monitoring": {
                "title": "Productivity vs Employee Privacy",
                "description": "Implementing monitoring tools for performance vs privacy concerns",
                "principles": ["Privacy", "Trust", "Productivity"]
            },
            "ai_decision_making": {
                "title": "AI Efficiency vs Algorithmic Fairness",
                "description": "Using AI for decisions while ensuring fairness and transparency",
                "principles": ["Fairness", "Transparency", "Accountability"]
            }
        }

        close_session(db)

        return render_template("ethical_decision_support.html",
                             ethical_decisions=ethical_decisions,
                             scenario_templates=scenario_templates)

    except Exception as e:
        close_session(db)
        flash(f"Error loading ethical decision support: {str(e)}", "error")
        return redirect(url_for('admin_dashboard'))


@app.route("/compliance_obligations", methods=["GET", "POST"])
@login_required
def compliance_obligations():
    """
    Compliance obligations management interface.

    Provides comprehensive view of regulatory requirements, compliance status,
    risk assessments, and remediation tracking across all frameworks.
    """
    user = current_user()
    db = get_session()

    if request.method == "POST":
        action = request.form.get('action')

        if action == "update_obligation":
            try:
                obligation_id = int(request.form.get('obligation_id'))
                obligation = db.query(ComplianceObligation).filter_by(id=obligation_id).first()

                if obligation:
                    # Update compliance score and assessment
                    obligation.current_compliance_score = float(request.form.get('compliance_score', 0))
                    obligation.last_assessed = datetime.now(timezone.utc)

                    # Update risk assessment
                    obligation.risk_likelihood = int(request.form.get('risk_likelihood', 3))
                    obligation.risk_impact = int(request.form.get('risk_impact', 3))
                    obligation.calculate_risk_score()

                    # Update remediation plan
                    obligation.remediation_plan = request.form.get('remediation_plan')
                    obligation.responsible_party = request.form.get('responsible_party')
                    obligation.timeline_days = int(request.form.get('timeline_days', 0)) if request.form.get('timeline_days') else None

                    db.commit()

                    log_audit_event(user, "COMPLIANCE_OBLIGATION_UPDATED", "COMPLIANCE",
                                  f"Updated obligation: {obligation.title}", "/compliance_obligations", True)

                    flash(f"Obligation '{obligation.title}' updated successfully!", "success")
                else:
                    flash("Compliance obligation not found.", "error")

            except Exception as e:
                db.rollback()
                flash(f"Error updating compliance obligation: {str(e)}", "error")

        elif action == "create_obligation":
            try:
                # Create new compliance obligation
                framework = ComplianceFramework(request.form.get('framework'))
                requirement_id = request.form.get('requirement_id')
                title = request.form.get('title')
                description = request.form.get('description')
                category = request.form.get('category')

                obligation = ComplianceObligation(
                    framework=framework,
                    requirement_id=requirement_id,
                    title=title,
                    description=description,
                    category=category,
                    mandatory=request.form.get('mandatory') == 'true',
                    priority_level=request.form.get('priority_level', 'medium')
                )

                db.add(obligation)
                db.commit()

                log_audit_event(user, "COMPLIANCE_OBLIGATION_CREATED", "COMPLIANCE",
                              f"Created obligation: {title}", "/compliance_obligations", True)

                flash(f"Compliance obligation '{title}' created successfully!", "success")

            except Exception as e:
                db.rollback()
                flash(f"Error creating compliance obligation: {str(e)}", "error")

        return redirect(url_for('compliance_obligations'))

    # GET request - show compliance obligations dashboard
    try:
        # Get all compliance obligations
        obligations = db.query(ComplianceObligation).order_by(
            ComplianceObligation.priority_level.desc(),
            ComplianceObligation.risk_score.desc()
        ).all()

        # Calculate compliance statistics
        total_obligations = len(obligations)
        compliant_obligations = sum(1 for o in obligations if o.get_compliance_status() == 'compliant')
        critical_obligations = sum(1 for o in obligations if o.priority_level == 'critical')
        high_risk_obligations = sum(1 for o in obligations if o.risk_score >= 13)

        # Framework breakdown
        framework_stats = {}
        for framework in ComplianceFramework:
            framework_obligations = [o for o in obligations if o.framework == framework]
            if framework_obligations:
                compliant = sum(1 for o in framework_obligations if o.get_compliance_status() == 'compliant')
                framework_stats[framework.value] = {
                    'total': len(framework_obligations),
                    'compliant': compliant,
                    'percentage': (compliant / len(framework_obligations)) * 100 if framework_obligations else 0
                }

        close_session(db)

        return render_template("compliance_obligations.html",
                             obligations=obligations,
                             total_obligations=total_obligations,
                             compliant_obligations=compliant_obligations,
                             critical_obligations=critical_obligations,
                             high_risk_obligations=high_risk_obligations,
                             framework_stats=framework_stats)

    except Exception as e:
        close_session(db)
        flash(f"Error loading compliance obligations: {str(e)}", "error")
        return redirect(url_for('admin_dashboard'))


@app.route("/compliance_risk_assessment", methods=["GET", "POST"])
@login_required
def compliance_risk_assessment():
    """
    Compliance risk assessment management interface.

    Provides tools for conducting comprehensive compliance risk assessments
    using standardized methodologies with automated scoring and reporting.
    """
    user = current_user()
    db = get_session()

    if request.method == "POST":
        action = request.form.get('action')

        if action == "create_assessment":
            try:
                # Create new compliance risk assessment
                title = request.form.get('title')
                scope = request.form.get('scope')
                assessment_type = request.form.get('assessment_type', 'comprehensive')
                methodology = request.form.get('methodology', 'NIST_SP_800_30')
                frameworks = request.form.getlist('frameworks')

                assessment = ComplianceRiskAssessment(
                    title=title,
                    scope=scope,
                    assessment_type=assessment_type,
                    methodology=methodology,
                    frameworks_assessed=json.dumps(frameworks),
                    lead_assessor=user.id,
                    status='planned'
                )

                db.add(assessment)
                db.commit()

                log_audit_event(user, "COMPLIANCE_RISK_ASSESSMENT_CREATED", "RISK",
                              f"Created assessment: {title}", "/compliance_risk_assessment", True)

                flash(f"Compliance risk assessment '{title}' created successfully!", "success")

            except Exception as e:
                db.rollback()
                flash(f"Error creating compliance risk assessment: {str(e)}", "error")

        elif action == "update_assessment":
            try:
                assessment_id = int(request.form.get('assessment_id'))
                assessment = db.query(ComplianceRiskAssessment).filter_by(id=assessment_id).first()

                if assessment:
                    # Update assessment results
                    assessment.findings_summary = request.form.get('findings_summary')
                    assessment.executive_summary = request.form.get('executive_summary')

                    # Update risk counts
                    assessment.risks_identified = int(request.form.get('risks_identified', 0))
                    assessment.critical_risks = int(request.form.get('critical_risks', 0))
                    assessment.high_risks = int(request.form.get('high_risks', 0))
                    assessment.medium_risks = int(request.form.get('medium_risks', 0))
                    assessment.low_risks = int(request.form.get('low_risks', 0))

                    # Update scores
                    assessment.overall_risk_score = float(request.form.get('overall_risk_score', 0))
                    assessment.compliance_score = float(request.form.get('compliance_score', 0))
                    assessment.recommendations_count = int(request.form.get('recommendations_count', 0))

                    # Update status
                    assessment.status = request.form.get('status', 'in_progress')
                    if assessment.status == 'completed':
                        assessment.completion_date = datetime.now(timezone.utc)

                    db.commit()

                    log_audit_event(user, "COMPLIANCE_RISK_ASSESSMENT_UPDATED", "RISK",
                                  f"Updated assessment: {assessment.title}", "/compliance_risk_assessment", True)

                    flash(f"Assessment '{assessment.title}' updated successfully!", "success")
                else:
                    flash("Assessment not found.", "error")

            except Exception as e:
                db.rollback()
                flash(f"Error updating assessment: {str(e)}", "error")

        return redirect(url_for('compliance_risk_assessment'))

    # GET request - show compliance risk assessment interface
    try:
        # Get all assessments
        assessments = db.query(ComplianceRiskAssessment).order_by(
            ComplianceRiskAssessment.created_at.desc()
        ).all()

        # Calculate assessment statistics
        total_assessments = len(assessments)
        completed_assessments = sum(1 for a in assessments if a.status == 'completed')
        in_progress_assessments = sum(1 for a in assessments if a.status == 'in_progress')

        # Risk distribution
        total_critical_risks = sum(a.critical_risks for a in assessments)
        total_high_risks = sum(a.high_risks for a in assessments)
        total_risks = sum(a.risks_identified for a in assessments)

        close_session(db)

        return render_template("compliance_risk_assessment.html",
                             assessments=assessments,
                             total_assessments=total_assessments,
                             completed_assessments=completed_assessments,
                             in_progress_assessments=in_progress_assessments,
                             total_critical_risks=total_critical_risks,
                             total_high_risks=total_high_risks,
                             total_risks=total_risks)

    except Exception as e:
        close_session(db)
        flash(f"Error loading compliance risk assessment: {str(e)}", "error")
        return redirect(url_for('admin_dashboard'))


@app.route("/compliance_incidents", methods=["GET", "POST"])
@login_required
def compliance_incidents():
    """
    Compliance incident management interface.

    Provides comprehensive incident tracking, classification, response coordination,
    and regulatory reporting for compliance incidents.
    """
    user = current_user()
    db = get_session()

    if request.method == "POST":
        action = request.form.get('action')

        if action == "create_incident":
            try:
                # Create new compliance incident
                title = request.form.get('title')
                category = request.form.get('category')
                severity = request.form.get('severity')
                description = request.form.get('description')

                # Incident details
                date_occurred_str = request.form.get('date_occurred')
                date_occurred = datetime.fromisoformat(date_occurred_str) if date_occurred_str else None
                discovery_method = request.form.get('discovery_method')

                # Impact assessment
                affected_individuals = int(request.form.get('affected_individuals', 0))
                affected_systems = request.form.get('affected_systems')
                business_impact = request.form.get('business_impact', 'low')
                financial_impact = float(request.form.get('financial_impact', 0))
                regulatory_impact = request.form.get('regulatory_impact')

                incident = ComplianceIncident(
                    title=title,
                    category=category,
                    severity=severity,
                    description=description,
                    date_occurred=date_occurred,
                    discovery_method=discovery_method,
                    affected_individuals=affected_individuals,
                    affected_systems=affected_systems,
                    business_impact=business_impact,
                    financial_impact=financial_impact,
                    regulatory_impact=regulatory_impact,
                    reported_by=user.id
                )

                db.add(incident)
                db.commit()

                # Generate incident ID after commit
                incident.generate_incident_id()
                db.commit()

                log_audit_event(user, "COMPLIANCE_INCIDENT_CREATED", "INCIDENT",
                              f"Created incident: {incident.incident_id}", "/compliance_incidents", True)

                flash(f"Compliance incident '{incident.incident_id}' created successfully!", "success")

            except Exception as e:
                db.rollback()
                flash(f"Error creating compliance incident: {str(e)}", "error")

        elif action == "update_incident":
            try:
                incident_id = int(request.form.get('incident_id'))
                incident = db.query(ComplianceIncident).filter_by(id=incident_id).first()

                if incident:
                    # Update incident details
                    incident.title = request.form.get('title')
                    incident.category = request.form.get('category')
                    incident.severity = request.form.get('severity')
                    incident.description = request.form.get('description')
                    incident.status = request.form.get('status', 'identified')

                    # Update investigation details
                    incident.root_cause = request.form.get('root_cause')
                    incident.contributing_factors = request.form.get('contributing_factors')
                    incident.investigation_findings = request.form.get('investigation_findings')

                    # Update response actions
                    incident.immediate_actions = request.form.get('immediate_actions')
                    incident.containment_actions = request.form.get('containment_actions')
                    incident.remediation_actions = request.form.get('remediation_actions')

                    # Update follow-up
                    incident.lessons_learned = request.form.get('lessons_learned')
                    incident.preventive_measures = request.form.get('preventive_measures')

                    # Update assignment
                    assigned_to = request.form.get('assigned_to')
                    if assigned_to:
                        incident.assigned_to = int(assigned_to)

                    # Mark as resolved if status is closed
                    if incident.status == 'closed':
                        incident.resolved_at = datetime.now(timezone.utc)

                    db.commit()

                    log_audit_event(user, "COMPLIANCE_INCIDENT_UPDATED", "INCIDENT",
                                  f"Updated incident: {incident.incident_id}", "/compliance_incidents", True)

                    flash(f"Incident '{incident.incident_id}' updated successfully!", "success")
                else:
                    flash("Incident not found.", "error")

            except Exception as e:
                db.rollback()
                flash(f"Error updating incident: {str(e)}", "error")

        return redirect(url_for('compliance_incidents'))

    # GET request - show compliance incidents dashboard
    try:
        # Get all incidents
        incidents = db.query(ComplianceIncident).order_by(
            ComplianceIncident.created_at.desc()
        ).all()

        # Calculate incident statistics
        total_incidents = len(incidents)
        open_incidents = sum(1 for i in incidents if i.status in ['identified', 'investigating', 'contained'])
        critical_incidents = sum(1 for i in incidents if i.severity == 'critical')
        high_severity_incidents = sum(1 for i in incidents if i.severity == 'high')

        # Category breakdown
        category_stats = {}
        for incident in incidents:
            category = incident.category
            if category not in category_stats:
                category_stats[category] = 0
            category_stats[category] += 1

        # Get users for assignment dropdown
        users = db.query(User).filter(User.role.in_(['admin', 'auditor'])).all()

        close_session(db)

        return render_template("compliance_incidents.html",
                             incidents=incidents,
                             total_incidents=total_incidents,
                             open_incidents=open_incidents,
                             critical_incidents=critical_incidents,
                             high_severity_incidents=high_severity_incidents,
                             category_stats=category_stats,
                             users=users)

    except Exception as e:
        close_session(db)
        flash(f"Error loading compliance incidents: {str(e)}", "error")
        return redirect(url_for('admin_dashboard'))
