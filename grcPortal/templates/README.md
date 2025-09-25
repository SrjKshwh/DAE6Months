# 🎨 Templates Directory

This directory contains all Jinja2 HTML templates for the GRC Portal web application, providing the user interface for the enterprise governance, risk, and compliance platform.

## 📂 Directory Structure

```
templates/
├── README.md                    # This documentation
├── base.html                    # 🔧 Main layout template
├── login.html                   # 🔐 Authentication page
├── register.html                # 📝 User registration
├── home.html                    # 🏠 Main dashboard
├── errors/                      # ⚠️ Error page templates
│   ├── 404.html                # Page not found
│   └── 500.html                # Server error
├── [Feature-specific templates] # Organized by functionality
├── risks.html                   # 📊 Risk register
├── risk_detail.html             # 📋 Individual risk view
├── risk_dashboard.html          # 📈 Risk analytics dashboard
├── compliance.html              # ✅ Compliance monitoring
├── incidents.html               # 🚨 Incident management
├── incident.html                # 📄 Individual incident
├── report_incident.html         # 📝 Incident reporting
├── forensics.html               # 🔍 Digital forensics
├── audit_logs.html              # 📋 Audit trail
├── policies.html                # 📚 Security policies
├── kb.html                      # 📖 Knowledge base
├── monitoring.html              # 📊 System monitoring
├── asset_register.html          # 💼 Critical asset management
├── asset_report.html            # 📊 Asset risk reports
├── framework_mapping.html       # 🗺️ Compliance framework mapping
├── risk_programs.html           # 📋 Program management
├── program_detail.html          # 📄 Program details
├── gap_analysis.html            # 🔍 Gap analysis interface
├── risk_indicators.html         # 📊 KPI monitoring
├── environmental_changes.html   # 🌍 Change management
├── brainstorming.html           # 💡 Risk brainstorming
├── brainstorming_session.html   # 👥 Session management
├── checklists.html              # 📝 Risk checklists
├── checklist_assessment.html    # ✅ Assessment interface
├── swot_analysis.html           # 📊 SWOT analysis
├── swot_analysis_detail.html    # 📈 SWOT results
├── create_program.html          # ➕ Program creation
└── admin_users.html             # 👑 User administration
```

## 🏗️ Template Architecture

### Base Template (base.html)
**Foundation template providing:**
- HTML5 structure with accessibility features
- Bootstrap 5 integration and responsive design
- Security headers and meta tags
- Navigation bar with role-based menu system
- Flash message system for user feedback
- Footer and common UI elements

**Key Features:**
- **Zero Trust UI**: Authentication checks in templates
- **Role-Based Rendering**: Conditional content based on user roles
- **Responsive Design**: Mobile-first approach with Bootstrap
- **Accessibility**: WCAG compliance with proper ARIA labels
- **Security**: XSS protection through Jinja2 auto-escaping

### Template Inheritance
```jinja2
<!-- Child template structure -->
{% extends "base.html" %}

{% block title %}Page Title - GRC Portal{% endblock %}

{% block content %}
<!-- Page-specific content -->
{% endblock %}

{% block scripts %}
<!-- Page-specific JavaScript -->
{% endblock %}
```

## 🎯 Template Categories

### 🔐 Authentication Templates
- **login.html**: Secure login form with validation
- **register.html**: User registration with password complexity
- **Errors (errors/)**: 404 and 500 error pages with helpful messaging

### 📊 Dashboard & Analytics
- **home.html**: Main application dashboard with recent activity
- **risk_dashboard.html**: Executive risk overview with KPIs
- **monitoring.html**: Real-time system monitoring and alerts

### 🎯 Risk Management
- **risks.html**: Comprehensive risk register with filtering
- **risk_detail.html**: Detailed risk view with mitigation plans
- **brainstorming.html**: Facilitated risk identification sessions
- **checklists.html**: Risk assessment checklists and templates
- **swot_analysis.html**: Strategic risk analysis matrix

### ✅ Compliance & Governance
- **compliance.html**: Multi-framework compliance monitoring
- **framework_mapping.html**: Organizational framework alignment
- **audit_logs.html**: Comprehensive audit trail and logging
- **policies.html**: Security policies and procedures
- **kb.html**: Knowledge base and reference materials

### 🚨 Incident Response
- **incidents.html**: Incident management dashboard
- **incident.html**: Detailed incident view with IRP tracking
- **report_incident.html**: Incident reporting form
- **forensics.html**: Digital evidence collection and analysis

### 📋 Program Management
- **risk_programs.html**: Program lifecycle management
- **program_detail.html**: Detailed program view with phases
- **gap_analysis.html**: Gap identification and remediation
- **create_program.html**: Program creation wizard

### 👑 Administrative
- **admin_users.html**: User management and role assignment
- **asset_register.html**: Critical asset inventory management
- **risk_indicators.html**: KPI configuration and monitoring
- **environmental_changes.html**: Change management tracking

## 🔧 Template Features

### Security Features
- **Input Validation**: Client and server-side validation
- **CSRF Protection**: Flask-WTF integration for forms
- **XSS Prevention**: Jinja2 auto-escaping enabled
- **Content Security**: Appropriate CSP headers
- **Authentication Checks**: Template-level access control

### UI/UX Features
- **Responsive Design**: Bootstrap 5 grid system
- **Interactive Elements**: Modals, dropdowns, accordions
- **Data Visualization**: Charts and progress indicators
- **Accessibility**: Screen reader support and keyboard navigation
- **Progressive Enhancement**: Graceful degradation

### Performance Features
- **Lazy Loading**: Content loaded on demand
- **Caching**: Template fragment caching where appropriate
- **Minification**: HTML minified in production
- **CDN Integration**: Static assets served optimally

## 📝 Template Development

### Best Practices
```jinja2
<!-- Use semantic HTML -->
<main class="container-fluid">
  <section class="card">
    <header class="card-header">
      <h2>Page Title</h2>
    </header>
    <div class="card-body">
      <!-- Content -->
    </div>
  </section>
</main>

<!-- Proper form handling -->
<form method="POST" novalidate>
  {{ form.hidden_tag() }}
  <div class="mb-3">
    {{ form.field.label(class="form-label") }}
    {{ form.field(class="form-control") }}
    {% if form.field.errors %}
      <div class="invalid-feedback">
        {% for error in form.field.errors %}
          {{ error }}
        {% endfor %}
      </div>
    {% endif %}
  </div>
</form>
```

### Naming Conventions
- **Files**: lowercase_with_underscores.html
- **Blocks**: semantic names (content, scripts, styles)
- **Variables**: descriptive names in snake_case
- **Classes**: Bootstrap classes with custom prefixes where needed

### Template Variables
```python
# Common variables passed to templates
{
    'current_user': user_object,        # Authenticated user
    'form': wtform_object,             # Form for POST requests
    'data': paginated_data,            # List/grid data
    'filters': filter_options,         # Available filters
    'stats': dashboard_stats,          # Summary statistics
    'navigation': menu_items           # Dynamic navigation
}
```

## 🔄 Template Maintenance

### Update Procedures
1. **Version Control**: All template changes tracked in Git
2. **Testing**: Cross-browser and responsive testing
3. **Accessibility**: Regular accessibility audits
4. **Performance**: Template rendering performance monitoring
5. **Security**: Regular security reviews and updates

### Quality Assurance
- **Code Reviews**: Peer review for all template changes
- **Automated Testing**: Template rendering tests
- **User Testing**: Usability testing with target users
- **Performance Testing**: Load testing for high-traffic pages

## 🚀 Future Enhancements

### Planned Improvements
- **Component System**: Reusable template components
- **Theming Engine**: Dynamic theme switching
- **Progressive Web App**: PWA template optimizations
- **Internationalization**: Multi-language template support
- **Advanced Interactions**: Enhanced JavaScript integrations

### Template Pipeline
- **Build Process**: Automated template optimization
- **Linting**: HTML and accessibility linting
- **Minification**: Production-ready optimization
- **Caching**: Intelligent template caching strategies

## 📊 Template Analytics

### Usage Metrics
- **Page Views**: Most accessed templates
- **Load Times**: Template rendering performance
- **Error Rates**: Template-related errors
- **Conversion Rates**: Goal completion rates

### Optimization Opportunities
- **Bundle Analysis**: Identify unused template code
- **Performance Profiling**: Slow-rendering template identification
- **User Experience**: Heat maps and interaction analysis
- **Accessibility Scores**: WCAG compliance tracking

---

**🎨 For detailed UI/UX implementation, see [../docs/index.md#uiux-implementation](../docs/index.md#uiux-implementation)**

**🔗 Back to main project: [../README.md](../README.md)**