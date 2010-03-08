/*
 * Copyright (c) 2002-2006
 * All rights reserved.
 */

package com.atlassian.jira.util;

import com.atlassian.core.ofbiz.CoreFactory;
import com.atlassian.core.user.UserUtils;
import com.atlassian.core.util.collection.EasyList;
import com.atlassian.core.util.map.EasyMap;
import com.atlassian.jira.ComponentManager;
import com.atlassian.jira.JiraException;
import com.atlassian.jira.action.project.ProjectUtils;
import com.atlassian.jira.bc.project.component.ProjectComponent;
import com.atlassian.jira.bc.project.component.ProjectComponentManager;
import com.atlassian.jira.config.ConstantsManager;
import com.atlassian.jira.config.properties.APKeys;
import com.atlassian.jira.config.properties.ApplicationProperties;
import com.atlassian.jira.exception.CreateException;
import com.atlassian.jira.exception.DataAccessException;
import com.atlassian.jira.external.ExternalUtils;
import com.atlassian.jira.external.beans.ExternalUser;
import com.atlassian.jira.issue.AttachmentManager;
import com.atlassian.jira.issue.CustomFieldManager;
import com.atlassian.jira.issue.Issue;
import com.atlassian.jira.issue.IssueFactory;
import com.atlassian.jira.issue.IssueFieldConstants;
import com.atlassian.jira.issue.IssueImpl;
import com.atlassian.jira.issue.IssueManager;
import com.atlassian.jira.issue.MutableIssue;
import com.atlassian.jira.issue.attachment.Attachment;
import com.atlassian.jira.issue.cache.CacheManager;
import com.atlassian.jira.issue.comments.CommentManager;
import com.atlassian.jira.issue.context.GlobalIssueContext;
import com.atlassian.jira.issue.customfields.CustomFieldSearcher;
import com.atlassian.jira.issue.customfields.CustomFieldType;
import com.atlassian.jira.issue.fields.CustomField;
import com.atlassian.jira.issue.fields.SummarySystemField;
import com.atlassian.jira.issue.fields.screen.issuetype.IssueTypeScreenSchemeManager;
import com.atlassian.jira.issue.history.ChangeItemBean;
import com.atlassian.jira.issue.history.ChangeLogUtils;
import com.atlassian.jira.issue.index.IndexException;
import com.atlassian.jira.issue.index.IssueIndexManager;
import com.atlassian.jira.issue.link.IssueLinkManager;
import com.atlassian.jira.issue.link.IssueLinkType;
import com.atlassian.jira.issue.link.IssueLinkTypeManager;
import com.atlassian.jira.issue.vote.VoteManager;
import com.atlassian.jira.issue.watchers.WatcherManager;
import com.atlassian.jira.issue.worklog.Worklog;
import com.atlassian.jira.issue.worklog.WorklogImpl;
import com.atlassian.jira.issue.worklog.WorklogManager;
import com.atlassian.jira.permission.PermissionSchemeManager;
import com.atlassian.jira.project.Project;
import com.atlassian.jira.project.ProjectManager;
import com.atlassian.jira.project.version.Version;
import com.atlassian.jira.project.version.VersionManager;
import com.atlassian.jira.scheme.SchemeManager;
import com.atlassian.jira.security.PermissionManager;
import com.atlassian.jira.security.Permissions;
import com.atlassian.jira.user.util.UserUtil;
import com.atlassian.jira.web.action.admin.customfields.CreateCustomField;
import com.atlassian.jira.web.action.util.BugzillaConnectionBean;
import com.atlassian.jira.workflow.WorkflowFunctionUtils;
import com.opensymphony.user.EntityNotFoundException;
import com.opensymphony.user.User;
import com.opensymphony.util.TextUtils;
import org.apache.commons.collections.set.ListOrderedSet;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.apache.oro.text.regex.MalformedPatternException;
import org.apache.oro.text.regex.MatchResult;
import org.apache.oro.text.regex.Pattern;
import org.apache.oro.text.regex.PatternMatcher;
import org.apache.oro.text.regex.PatternMatcherInput;
import org.apache.oro.text.regex.Perl5Compiler;
import org.apache.oro.text.regex.Perl5Matcher;
import org.apache.oro.text.regex.Substitution;
import org.apache.oro.text.regex.Util;
import org.ofbiz.core.entity.GenericDelegator;
import org.ofbiz.core.entity.GenericEntityException;
import org.ofbiz.core.entity.GenericValue;
import org.ofbiz.core.util.UtilDateTime;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class BugzillaImportBean
{
    private static final Logger log4jLog = Logger.getLogger(BugzillaImportBean.class);
    private static final String BUGZILLA_CHANGE_ITEM_FIELD = "phpBB Import Key";
    private final IssueIndexManager indexManager;
    private final GenericDelegator genericDelegator;
    private final ProjectManager projectManager;
    private final SchemeManager permissionSchemeManager;
    private final CacheManager cacheManager;
    private final VersionManager versionManager;
    private final VoteManager voteManager;
    private final ProjectComponentManager projectComponentManager;
    private final IssueManager issueManager;
    private final AttachmentManager attachmentManager;
    private final IssueTypeScreenSchemeManager issueTypeScreenSchemeManager;
    private final CustomFieldManager customFieldManager;
    private final PermissionManager permissionManager;
    private final IssueLinkManager issueLinkManager;
    private final IssueLinkTypeManager issueLinkTypeManager;
    private final ConstantsManager constantsManager;
    private final ExternalUtils externalUtils;
    private final CommentManager commentManager;
    private final ApplicationProperties applicationProperties;
    private final WatcherManager watcherManager;
    private final UserUtil userUtil;
    private final Set truncSummaryIssueKeys = new ListOrderedSet();

    StringBuffer importLog = null;

    //these are cached lookups to save us having to go to the database each time.
    private final Map userKeys = new HashMap(255);
    // Map of lowercase'd project names to JIRA Project GVs
    private final Map projectKeys = new HashMap();

    // Map from Bugzilla user id to Jira User
    private final Map versionKeys = new HashMap();
    private final Map componentKeys = new HashMap();

    // bugzilla -> jira issue key mappings
    private Map previouslyImportedKeys = new HashMap(); // issues imported at any time (this or earlier runs)
    private Map importedKeys = new HashMap(); // Map of bugzilla ids (Integer) to Jira ids (Long) of issues imported during this run
    private String selectedProjects;
    private User importer;
    private BugzillaMappingBean bugzillaMappingBean;
    private boolean reuseExistingUsers;
    private boolean workHistory;
    private final Map projectToBugzillaIdMap = new HashMap();
    private boolean onlyNewIssues;

    public static final String BUGZILLA_ID_TYPE = "importid";
    public static final String BUGZILLA_ID_SEARCHER = "exactnumber";
    public static final String BUGZILLA_ID_CF_NAME = "phpBB Bug Id";
    private CustomField bugzillaIdCustomField;
    private boolean cryptedPasswords = false;
    private PreparedStatement profilePS;
    private PreparedStatement componentPS;
    private PreparedStatement productPS;
    private PreparedStatement commentPS;
    private final IssueFactory issueFactory;
    private final WorklogManager worklogManager;

    public BugzillaImportBean(final IssueIndexManager indexManager, final GenericDelegator genericDelegator, final ProjectManager projectManager, final PermissionSchemeManager permissionSchemeManager, final CacheManager cacheManager, final VersionManager versionManager, final VoteManager voteManager, final ProjectComponentManager projectComponentManager, final CustomFieldManager customFieldManager, final IssueManager issueManager, final AttachmentManager attachmentManager, final IssueTypeScreenSchemeManager issueTypeScreenSchemeManager, final PermissionManager permissionManager, final IssueLinkManager issueLinkManager, final IssueLinkTypeManager issueLinkTypeManager, final ConstantsManager constantsManager, final ExternalUtils externalUtils, final CommentManager commentManager, final IssueFactory issueFactory, final WorklogManager worklogManager, final ApplicationProperties applicationProperties, final WatcherManager watcherManager, final UserUtil userUtil)
    {
        this.indexManager = indexManager;
        this.genericDelegator = genericDelegator;
        this.projectManager = projectManager;
        this.permissionSchemeManager = permissionSchemeManager;
        this.cacheManager = cacheManager;
        this.versionManager = versionManager;
        this.voteManager = voteManager;
        this.projectComponentManager = projectComponentManager;
        this.customFieldManager = customFieldManager;
        this.issueManager = issueManager;
        this.attachmentManager = attachmentManager;
        this.issueTypeScreenSchemeManager = issueTypeScreenSchemeManager;
        this.permissionManager = permissionManager;
        this.issueLinkManager = issueLinkManager;
        this.issueLinkTypeManager = issueLinkTypeManager;
        this.constantsManager = constantsManager;
        this.externalUtils = externalUtils;
        this.commentManager = commentManager;
        this.issueFactory = issueFactory;
        this.worklogManager = worklogManager;
        this.applicationProperties = applicationProperties;
        this.watcherManager = watcherManager;
        this.userUtil = userUtil;
    }

    /**
     * This method will determine all the users that will need to exist in JIRA to successfully import the
     * specified projects and will return the users that do not yet exist.
     *
     * @param connectionBean initialized connection bean
     * @param projectNames   the projects, by bugzilla project name, that you want to import.
     * @return Set <ExternalUser> all the users that will need to exist in JIRA but do not yet.
     */
    public Set getNonExistentAssociatedUsers(final BugzillaConnectionBean connectionBean, final String[] projectNames)
    {
        return ImportUtils.getNonExistentUsers(getAssociatedUsers(connectionBean, projectNames));
    }

    /**
     * Main method of this bean.  Creates JIRA projects mirroring those found in a Bugzilla database.
     *
     * @param bugzillaMappingBean Mappings from Bugzilla to JIRA, including project key, statuses, etc
     * @param connectionBean      Bugzilla connection bean
     * @param enableNotifications Whether to send email notifications for newly created issues
     * @param reuseExistingUsers  Do we try to reuse existing users, or create a unique user for every Bugzilla user?
     * @param onlyNewIssues       Should we only import issues that haven't previously been imported (to avoid duplicates)?
     * @param reindex             Whether to reindex after the import
     * @param workHistory         Whether to import work history as well
     * @param projectNames        Array of Bugzilla project names to import
     * @param importer            User performing the import operation
     * @throws Exception if something goes wrong
     */
    public void create(final BugzillaMappingBean bugzillaMappingBean, final BugzillaConnectionBean connectionBean, final boolean enableNotifications, final boolean reuseExistingUsers, final boolean onlyNewIssues, final boolean reindex, final boolean workHistory, final String[] projectNames, final User importer) throws Exception
    {
        importLog = new StringBuffer(1024 * 30);
        if (projectNames.length == 0)
        {
            log("No projects selected for import");
            return;
        }
        this.bugzillaMappingBean = bugzillaMappingBean;
        this.reuseExistingUsers = reuseExistingUsers;
        this.onlyNewIssues = onlyNewIssues;
        this.workHistory = workHistory;

        //todo - clear userKeys, projectKeys etc
        this.importer = importer;

        try
        {
            final long starttime = System.currentTimeMillis();

            createOrFindCustomFields();

            selectedProjects = ImportUtils.getSQLTokens(projectNames);

            final Connection conn = connectionBean.getConnection();
            createPreparedStatements(conn);

            ImportUtils.setSubvertSecurityScheme(true);
            if (reindex)
            {
                ImportUtils.setIndexIssues(false);
            }
            ImportUtils.setEnableNotifications(enableNotifications);

            createProjects(projectNames, conn);
            createVersions(conn);
            createComponents(conn);

            // if non-lazy: createUsers();

            createIssues(conn);

            rewriteBugLinks();

            ImportUtils.setSubvertSecurityScheme(false); // before the reindex, so pico-instantiated-during-reindex components don't get the wrong thing. JRA-7638
            if (reindex)
            {
                ImportUtils.setIndexIssues(true);
            }

			// Votes are not used in the phpBB.com database
			// createVotes(conn);

            createWatchers(conn);
            if (reindex)
            {
                log("Reindexing (this may take a while)...");
                indexManager.reIndexAll();
            }

            final long endtime = System.currentTimeMillis();
            log("\nImport SUCCESS and took: " + (endtime - starttime) + " ms.");
        }
        finally
        {
            closePreparedStatements();
            connectionBean.closeConnection();
            ImportUtils.setSubvertSecurityScheme(false); // do again just in case we failed before the reindex
            if (reindex)
            {
                ImportUtils.setIndexIssues(true);
            }
            if (!enableNotifications)
            {
                ImportUtils.setEnableNotifications(true);
            }
        }
    }

    private void createPreparedStatements(final Connection conn) throws SQLException
    {
        componentPS = conn.prepareStatement("select name from components where id = ?");
        productPS = conn.prepareStatement("select name from products where id = ?");

		/*if (tableHasColumn(conn, "profiles", "cryptpassword"))
        {
            cryptedPasswords = true;
            profilePS = conn.prepareStatement("SELECT userid, login_name, realname FROM profiles where userid = ?");
        }
        else
        {
            cryptedPasswords = false;
            profilePS = conn.prepareStatement("SELECT userid, login_name, realname, password FROM profiles where userid = ?");
        }
		*/

		// Prepared Statement for profiles
		cryptedPasswords = true;
		profilePS = conn.prepareStatement("SELECT user_id, username, user_email, username as realname FROM community_users WHERE user_id = ?");

        commentPS = conn.prepareStatement("SELECT thetext, who, bug_when FROM longdescs WHERE bug_id = ? ORDER BY bug_when ASC");
    }

    private void closePreparedStatements() throws SQLException
    {
        if (componentPS != null)
        {
            componentPS.close();
        }
        if (productPS != null)
        {
            productPS.close();
        }
        if (profilePS != null)
        {
            profilePS.close();
        }
        if (commentPS != null)
        {
            commentPS.close();
        }
    }

    private void createIssues(final Connection conn) throws Exception
    {
        int count = 0;
        log("\n\nImporting Issues from project(s) " + selectedProjects);

        // use the changeItem importLog to retrieve the list of issues previously imported from Bugzilla
        previouslyImportedKeys = retrieveImportedIssues();

        String sql = "SELECT * FROM bugs where ";
        sql += whereSelectedProjectClauseForVersionsAndComponents();

        final PreparedStatement preparedStatement = conn.prepareStatement(sql);
        final ResultSet resultSet = preparedStatement.executeQuery();
        importedKeys = new HashMap();

        final PreparedStatement attachPrepStatement = conn.prepareStatement("SELECT * FROM attachments WHERE bug_id = ? ORDER BY attach_id ASC");
        final PreparedStatement linkDependsOnPrepStatement = conn.prepareStatement("SELECT dependson FROM dependencies WHERE blocked = ?");
        final PreparedStatement linkBlocksPrepStatement = conn.prepareStatement("SELECT blocked FROM dependencies WHERE dependson = ?");
        final PreparedStatement linkDuplicatesStatement = conn.prepareStatement("SELECT dupe FROM duplicates WHERE dupe_of = ?");
        final PreparedStatement linkDuplicatedOfStatement = conn.prepareStatement("SELECT dupe_of FROM duplicates WHERE dupe = ?");

        final IssueLinkType dependencyLinkType = createOrFindLinkType("Dependency", "depends on", "blocks");
        final IssueLinkType duplicateLinkType = createOrFindLinkType("Duplicate", "duplicates", "is duplicated by");

        truncSummaryIssueKeys.clear();
        while (resultSet.next())
        {
            if (!onlyNewIssues || !previouslyImportedKeys.containsKey(new Integer(resultSet.getInt("bug_id"))))
            {
                log("Importing Issue: \"" + resultSet.getString("short_desc") + "\"");

                String componentName;
                try
                {
                    componentName = resultSet.getString("component");
                }
                catch (final SQLException e)
                {
                    componentName = getComponentName(resultSet.getInt("component_id"));
                }

                final int bugId = resultSet.getInt("bug_id");
                try
                {
                    final GenericValue issue = createIssue(resultSet, getProductName(resultSet, true), componentName);
                    createCommentAndDescription(bugId, issue);
                    // NOTE: this call has not been tested, we are waiting for test data, that is why it is surrounded
                    // in a conditional
                    if (workHistory)
                    {
                        createWorkHistory(conn, bugId, issueFactory.getIssue(issue));
                    }
                    createAttachments(conn, attachPrepStatement, bugId, issue);

                    if (applicationProperties.getOption(APKeys.JIRA_OPTION_ISSUELINKING))
                    {
                        createLinks(dependencyLinkType, "blocked", "dependson", linkBlocksPrepStatement, linkDependsOnPrepStatement, bugId, issue);
                        createLinks(duplicateLinkType, "dupe", "dupe_of", linkDuplicatesStatement, linkDuplicatedOfStatement, bugId, issue);
                    }
                    else
                    {
                        // NOTE: should not occur, i enabled issue linking for duplicates (Meik)
						log("Issue links will not be imported from bugzilla since issue linking is disabled in JIRA.");
                    }

                }
                catch (final Exception e)
                {
                    log("Exception processing bug id " + bugId);
                    throw (e);
                }

                count++;
            }
            else
            {
                log("Not re-importing issue: \"" + resultSet.getString("short_desc") + "\"");
            }
        }
        log(count + " issues imported from Bugzilla.");

        ImportUtils.closePS(preparedStatement);
        ImportUtils.closePS(attachPrepStatement);
        ImportUtils.closePS(linkBlocksPrepStatement);
        ImportUtils.closePS(linkDependsOnPrepStatement);
    }

    private String getComponentName(final int componentId) throws SQLException
    {
        componentPS.setInt(1, componentId);
        final ResultSet rs = componentPS.executeQuery();
        rs.next();
        final String name = rs.getString("name");
        rs.close();
        return name;
    }

    private GenericValue createIssue(final ResultSet resultSet, final String productName, final String componentName) throws IndexException, SQLException, GenericEntityException, CreateException
    {
        final Map fields = new HashMap();
        final MutableIssue issueObject = IssueImpl.getIssueObject(null);
        issueObject.setProject(getProject(productName));
        issueObject.setReporter(getUser(resultSet.getInt("reporter")));
        issueObject.setAssignee(getUser(resultSet.getInt("assigned_to")));
        if (resultSet.getString("bug_severity").equals("enhancement"))
        {
            issueObject.setIssueTypeId(getEnhancementIssueTypeId());
        }
        else
        {
            issueObject.setIssueTypeId(getBugIssueTypeId());
        }

        // truncate summary if necessary - JRA-12837
        final int summaryMaxLength = SummarySystemField.MAX_LEN.intValue();
        String summary = resultSet.getString("short_desc");
        final boolean isSummaryTruncated;
        if (summary.length() > summaryMaxLength)
        {
            summary = summary.substring(0, summaryMaxLength);
            isSummaryTruncated = true;
        }
        else
        {
            isSummaryTruncated = false;
        }
        issueObject.setSummary(summary);

        // Make sure that the priority is in lower case. JRA-9586
        String priorityString = resultSet.getString("bug_severity");
        if (priorityString != null)
        {
            priorityString = priorityString.toLowerCase();
        }
        issueObject.setPriorityId(bugzillaMappingBean.getPriority(priorityString));

        final StringBuffer environment = new StringBuffer();

        environment.append("Operating System: ").append(resultSet.getString("op_sys")).append("\nPlatform: ").append(
            resultSet.getString("rep_platform"));

        final String url = resultSet.getString("bug_file_loc");
        if (!"".equals(url))
        {
            environment.append("\nURL: ").append(url);
        }

        issueObject.setEnvironment(environment.toString());

        // setup the associations with components/versions
        final String version = resultSet.getString("version");
        final String fixversion = resultSet.getString("target_milestone");
        createVersionComponentAssociations(issueObject, productName, version, componentName, fixversion);

        // NOTE: this call has not been tested, we are waiting for test data, that is why it is surrounded
        // in a conditional
        if (workHistory && !resultSet.getString("estimated_time").equals(""))
        {
            long time_original_estimate, time_remaining;
            time_original_estimate = (long) (3600.0 * resultSet.getFloat("estimated_time"));
            time_remaining = (long) (3600.0 * resultSet.getFloat("remaining_time"));

            issueObject.setOriginalEstimate(new Long(time_original_estimate));
            issueObject.setTimeSpent(new Long(time_remaining));
        }
        fields.put("issue", issueObject);
        final GenericValue origianlIssueGV = ComponentManager.getInstance().getIssueManager().getIssue(issueObject.getId());
        fields.put(WorkflowFunctionUtils.ORIGINAL_ISSUE_KEY, IssueImpl.getIssueObject(origianlIssueGV));

        final GenericValue issue = issueManager.createIssue(importer, fields);

        if (isSummaryTruncated)
        {
            truncSummaryIssueKeys.add(issue.getString("key"));
        }

        final String bugzillaStatus = resultSet.getString("bug_status");
        String jiraBugStatus = bugzillaMappingBean.getStatus(bugzillaStatus);
        boolean foundStatus = true;
        // JRA-10017 - always fall back to the open status if we can't find the correct status
        if (jiraBugStatus == null)
        {
            foundStatus = false;
            jiraBugStatus = String.valueOf(IssueFieldConstants.OPEN_STATUS_ID);
        }
        issue.set(IssueFieldConstants.STATUS, jiraBugStatus);

        // make sure no resolution if the issue is unresolved
        if (!"5".equals(jiraBugStatus) && !"6".equals(jiraBugStatus))
        {
            issue.set(IssueFieldConstants.RESOLUTION, null);
        }
        else
        {
            final String resolution = bugzillaMappingBean.getResolution(resultSet.getString("resolution"));
            issue.set(IssueFieldConstants.RESOLUTION, resolution);
            //If the issue is resolved, also set the resolution date (the mapping may return null meaning unresolved).
            //We'll use the last updated time for this, since bugzilla doesn't seem to store a resolution date.
            if(resolution != null)
            {
                issue.set(IssueFieldConstants.RESOLUTION_DATE, resultSet.getTimestamp("delta_ts"));
            }
        }

        issue.set(IssueFieldConstants.CREATED, resultSet.getTimestamp("creation_ts"));
        //Previously the import always set the updated date to the time of the import.  This has been
        //changed to use the last updated time from the database.
        issue.set(IssueFieldConstants.UPDATED, resultSet.getTimestamp("delta_ts"));
        issue.store();
        setCurrentWorkflowStep(issue);

        final int bugzillaId = resultSet.getInt("bug_id");
        createChangeHistory(bugzillaId, issue);
        previouslyImportedKeys.put(new Integer(bugzillaId), issue.getLong("id"));

        importedKeys.put(new Integer(bugzillaId), issue.getLong("id"));

        // Create custom field value for the issue
        if (bugzillaIdCustomField != null)
        {
            bugzillaIdCustomField.createValue(IssueImpl.getIssueObject(issue), new Double(bugzillaId));

            indexManager.reIndex(issue);
        }
        else
        {
            log("Bugzilla Id customfield not found. Bugzilla Id not added.");
        }

        if (!foundStatus)
        {
            log("Creating issue: " + issue.getString("key") + " for bugzilla issue: " + bugzillaId + " we could not find a mapping for Bugzilla status " + bugzillaStatus + ", defaulting to JIRA status Open");
        }

        return issue;
    }

    private String getEnhancementIssueTypeId()
    {
        if (constantsManager.getIssueType(BugzillaMappingBean.JIRA_ENHANCEMENT_ISSUE_TYPE_ID) != null)
        {
            return BugzillaMappingBean.JIRA_ENHANCEMENT_ISSUE_TYPE_ID;
        }
        else
        {
            log("ERROR: JIRA does not have an enhancement issue type with id " + BugzillaMappingBean.JIRA_ENHANCEMENT_ISSUE_TYPE_ID + "; creating as Bug instead");
            return getBugIssueTypeId();
        }
    }

    private String getBugIssueTypeId()
    {
        if (constantsManager.getIssueType(BugzillaMappingBean.JIRA_BUG_ISSUE_TYPE_ID) != null)
        {
            return BugzillaMappingBean.JIRA_BUG_ISSUE_TYPE_ID;
        }
        else
        {
            final Collection issueTypes = constantsManager.getIssueTypes();
            if (issueTypes.isEmpty())
            {
                throw new RuntimeException("No JIRA issue types defined!");
            }
            final String firstIssueType = ((GenericValue) issueTypes.iterator().next()).getString("id");
            log("ERROR: JIRA does not have a bug issue type with id " + BugzillaMappingBean.JIRA_BUG_ISSUE_TYPE_ID + "; using first found issue type " + firstIssueType + " instead.");
            return firstIssueType;
        }

    }

    /**
     * Associate the issue with a single version and component.  This is ok, as bugzilla only allows for a single
     * version and component for an issue.
     *
     * @param issue      issue
     * @param project    project
     * @param version    affects version
     * @param component  component
     * @param fixVersion fix version
     */
    private void createVersionComponentAssociations(final MutableIssue issue, final String project, final String version, final String component, final String fixVersion)
    {
        final Version verKey = getVersion(project + ":" + version);
        final Version fixverKey = getVersion(project + ":" + fixVersion);
        if (verKey != null)
        {
            final Version affectsVersion = versionManager.getVersion(verKey.getLong("id"));
            issue.setAffectedVersions(EasyList.build(affectsVersion));
        }
        else
        {
            if (log4jLog.isEnabledFor(Priority.ERROR))
            {
                log4jLog.error("Could not find version '" + project + ":" + version + "' to associate with issue " + issue);
            }
        }

        if (fixverKey != null)
        {
            final Version fixVer = versionManager.getVersion(fixverKey.getLong("id"));
            issue.setFixVersions(EasyList.build(fixVer));
        }
        else
        {
            // Ignore. Bugzilla (2.1.18) sets target_milestone="---" for issues without a target milestone, and as '---' is a
            // nonexistent version, we get to here.
        }

        final GenericValue comp = getComponent(project + ":" + component);
        if (comp != null)
        {
            final GenericValue affectsComponent = projectManager.getComponent(comp.getLong("id"));
            issue.setComponents(EasyList.build(affectsComponent));
        }
        else
        {
            if (log4jLog.isEnabledFor(Priority.ERROR))
            {
                log4jLog.error("Could not find component " + project + ":" + component + " to associate with issue " + issue);
            }
        }
    }

    /**
     * Given an issue, update the underlying workflow, so that it matches the issues status.
     *
     * @param issue issue generic value
     * @throws GenericEntityException if workflow step fails to be persisted
     */
    private void setCurrentWorkflowStep(final GenericValue issue) throws GenericEntityException
    {
        // retrieve the wfCurrentStep for this issue and change it
        final Collection wfCurrentStepCollection = genericDelegator.findByAnd("OSCurrentStep", EasyMap.build("entryId", issue.getLong("workflowId")));
        final GenericValue wfCurrentStep = (GenericValue) getOnly(wfCurrentStepCollection);
        wfCurrentStep.set("stepId", bugzillaMappingBean.getWorkflowStep(issue.getString("status")));
        wfCurrentStep.set("status", bugzillaMappingBean.getWorkflowStatus(issue.getString("status")));
        wfCurrentStep.store();
    }

    private void createCommentAndDescription(final int bug_id, final GenericValue issue) throws Exception
    {
        String description = null;
        commentPS.setInt(1, bug_id);

        final ResultSet resultSet = commentPS.executeQuery();
        while (resultSet.next())
        {
            // the description entry for each bug is JIRA's description, the rest goes into comments.
            if (resultSet.isFirst())
            {
                description = resultSet.getString("thetext");
            }
            else
            {
                final User user = getUser(resultSet.getInt("who"));

                // check permissions first
                if (!permissionManager.hasPermission(Permissions.COMMENT_ISSUE, issue, user))
                {
                    log("You (" + user.getFullName() + ") do not have permission to comment on an issue in project: " + projectManager.getProjectObj(
                        issue.getLong("project")).getName());
                }
                else
                {
                    final String author = user.getName();
                    final Date timePerformed = resultSet.getTimestamp("bug_when");
                    commentManager.create(issueFactory.getIssue(issue), author, author, resultSet.getString("thetext"), null, null, timePerformed,
                        timePerformed, false, false);
                }
            }
        }
        resultSet.close();

        issue.set("description", description);
        issue.store();
        cacheManager.flush(CacheManager.ISSUE_CACHE, issue); // Flush the cache, otherwise later when we look up the issue we'll get something stale. JRA-5542
    }

    // NOTE: this is untested code submitted by Vincent Fiano, we still need some test data to run through this
    private void createWorkHistory(final Connection conn, final int bug_id, final Issue issue) throws SQLException, JiraException
    {
        final PreparedStatement preparedStatement = conn.prepareStatement("SELECT * FROM bugs_activity WHERE bug_id = ? AND fieldid = 45 ORDER BY bug_when ASC");
        preparedStatement.setInt(1, bug_id);

        final ResultSet resultSet = preparedStatement.executeQuery();
        while (resultSet.next())
        {
            final User user = getUser(resultSet.getInt("who"));
            log("Adding work history for bug " + bug_id + ": " + new Float(resultSet.getFloat("added")) + " hours worked by " + getUser(resultSet.getInt("who")) + " on " + resultSet.getTimestamp("bug_when"));
            final Worklog worklog = new WorklogImpl(worklogManager, issue, null, user.getName(),
                "(see comment dated " + resultSet.getTimestamp("bug_when") + ")", resultSet.getTimestamp("bug_when"), null, null, new Long(
                    (long) (3600.0 * resultSet.getFloat("added"))));
            worklogManager.create(user, worklog, null, false);
        }
    }

    /**
     * Store the original bugzilla bug id in the change history.
     *
     * @param bug_id bug id
     * @param issue  issue
     */
    private void createChangeHistory(final int bug_id, final GenericValue issue)
    {
        // create a change group and change item for each issue imported to record the original Bugzilla id.
        // change items used to make sure issues are not duplicated
        final List changeItems = EasyList.build(new ChangeItemBean(ChangeItemBean.STATIC_FIELD, BUGZILLA_CHANGE_ITEM_FIELD, null,
            Integer.toString(bug_id), null, issue.getLong("id").toString()));
        ChangeLogUtils.createChangeGroup(importer, issue, issue, changeItems, true);
    }

    private void createWatchers(final Connection conn) throws SQLException
    {
        log("\n\nImporting Watchers");

        int count = 0;
        final PreparedStatement preparedStatement = conn.prepareStatement("SELECT who FROM cc WHERE bug_id = ?");
        final Iterator bugzillaBugIdIter = previouslyImportedKeys.keySet().iterator();
        // for each imported bug..
        while (bugzillaBugIdIter.hasNext())
        {
            final Integer bugzillaBugId = (Integer) bugzillaBugIdIter.next();
            preparedStatement.setInt(1, bugzillaBugId.intValue());
            final ResultSet rs = preparedStatement.executeQuery();
            // for each watcher of an imported bug..
            while (rs.next())
            {
                try
                {
                    final User watcher = getUser(rs.getInt("who")); // find or create the watcher
                    final Long jiraBugId = (Long) previouslyImportedKeys.get(bugzillaBugId);
                    final GenericValue issue = issueManager.getIssue(jiraBugId);
                    watcherManager.startWatching(watcher, issue);
                    count++;
                }
                catch (final SQLException e)
                {
                    final String err = "Failed to add a watcher to issue with Bugzilla id '" + bugzillaBugId + "': " + e.getMessage();
                    log(err);
                    log4jLog.warn(err, e);
                }
                catch (final RuntimeException e)
                {
                    final String err = "Failed to add a watcher to issue with Bugzilla id '" + bugzillaBugId + "': " + e.getMessage();
                    log(err);
                    log4jLog.warn(err, e);
                }
            }
        }
        ImportUtils.closePS(preparedStatement);
        log(count + " watchers imported from Bugzilla.");
    }

    /**
     * Return a map of bugzillaKey (Integer) -> Jira Issues Id (Integer).
     * <p/>
     * It does this by looking through the change items for the bugzilla import key.
     *
     * @return map of previously imported keys (old to new)
     * @throws GenericEntityException if cannot read from change items
     */
    protected Map retrieveImportedIssues() throws GenericEntityException
    {
        final Map previousKeys = new HashMap();

        // get the issues previously imported from Bugzilla via the change items.
        final Collection changeItems = genericDelegator.findByAnd("ChangeItem", EasyMap.build("field", BUGZILLA_CHANGE_ITEM_FIELD));
        for (final Iterator iterator = changeItems.iterator(); iterator.hasNext();)
        {
            final GenericValue changeItem = (GenericValue) iterator.next();
            previousKeys.put(new Integer(changeItem.getString("oldstring")), new Long(changeItem.getString("newstring")));
        }
        return previousKeys;
    }

    private void createComponents(final Connection conn) throws SQLException
    {
        int componentCount = 0;
        log("\n\nImporting Components from project(s) " + selectedProjects + "\n");

        final PreparedStatement preparedStatement = conn.prepareStatement("SELECT * FROM components where " + whereSelectedProjectClauseForVersionsAndComponents());
        final ResultSet resultSet = preparedStatement.executeQuery();
        String componentLead = null;
        String component = null;
        while (resultSet.next())
        {
            try
            {
                // lookup the component lead (only available in Enterprise)
                componentLead = getComponentLead(resultSet.getInt("initialowner"));
                component = resultSet.getString("name");
            }
            catch (final SQLException ex)
            {
                if (component != null)
                {
                    final String err = "Failed to retreive the default assignee of component '" + component + "'";
                    log(err);
                    log4jLog.warn(err, ex);
                }
                else
                {
                    final String err = "Failed to retrieve a component from Bugzilla";
                    log(err);
                    log4jLog.error(err, ex);
                }
            }
            log("Importing Component: " + component);

            final boolean created = createComponent(getProductName(resultSet, false), component, componentLead, resultSet.getString("description"));
            if (created)
            {
                componentCount++;
            }
        }
        log(componentCount + " components imported from Bugzilla.");
        ImportUtils.closePS(preparedStatement);
    }

    private String getComponentLead(final int defaultAssigneeId) throws SQLException
    {
        String componentLead = null;
        profilePS.clearParameters();
        profilePS.setInt(1, defaultAssigneeId);
        final ResultSet componentLeadResultSet = profilePS.executeQuery();
        if (componentLeadResultSet.next())
        {
            componentLead = componentLeadResultSet.getString("username");
        }
        return componentLead;
    }

    /**
     * Handles the different database schemata to retrieve the product name.
     * The program and product columns have been replaced with a FK pointing to
     * the name in the products table in 2.17.
     * <p/>
     * In 2.16, the product name for BUGS are listed in the product column
     * For COMPONENTS and VERSIONS, they are listed in the program column
     *
     * @param resultSet     result set containing product information
     * @param isBugzillaBug is bugzilla flag
     * @return product name
     * @throws SQLException if reading from result set fails
     */
    private String getProductName(final ResultSet resultSet, final boolean isBugzillaBug) throws SQLException
    {
        String projectName;
        try
        {
            // 2.17+ format
            final int pid = resultSet.getInt("product_id");
            if (pid == 0)
            {
                throw new RuntimeException("Null product_id for " + resultSet);
            }
            productPS.setInt(1, pid);
            final ResultSet rs = productPS.executeQuery();
            final boolean hasNext = rs.next();
            if (!hasNext)
            {
                throw new RuntimeException("No product with ID " + pid);
            }
            projectName = rs.getString("name");
            rs.close();
        }
        catch (final SQLException e)
        {
            // If we don't have a product_id, we may be using Bugzilla 2.16 or earlier. In this case, the resultSet
            // may be for the components or bugs tables:
            if (isBugzillaBug)
            {
                projectName = resultSet.getString("product");
            }
            else
            {
                projectName = resultSet.getString("program");
            }
        }
        return projectName;
    }

    private boolean createComponent(final String projectName, final String componentName, final String componentLead, final String description)
    {
        final GenericValue project = getProject(projectName);
        final GenericValue existingComponent = projectManager.getComponent(project, componentName);

        // if the componentName exists already, do not import
        if (existingComponent != null)
        {
            log("Component " + componentName + " in Project: " + projectName + " already exists. Not imported");
            componentKeys.put(projectName + ":" + componentName, existingComponent);
            return false;
        }
        else
        {
            try
            {
                final ProjectComponent projectComponent = projectComponentManager.create(componentName, description, componentLead, 0,
                    project.getLong("id"));
                final GenericValue componentGV = projectComponentManager.convertToGenericValue(projectComponent);

                // imported components are stored for use later
                componentKeys.put(projectName + ":" + componentName, componentGV);
                return true;
            }
            catch (final Exception e)
            {
                log("Error importing Component: " + componentName);
                log(ExceptionUtils.getStackTrace(e));
                return false;
            }
        }
    }

    private void createVersions(final Connection conn) throws SQLException
    {
        log("\n\nImporting Versions from project " + selectedProjects + "\n");

        createVersionFromVersionTable(conn);
        createVersionFromBugsTable(conn);
    }

    private void createVersionFromVersionTable(final Connection conn) throws SQLException
    {
        int count = 0;

        final String sql = "select * from versions where " + whereSelectedProjectClauseForVersionsAndComponents();
        final PreparedStatement preparedStatement = conn.prepareStatement(sql);
        final ResultSet resultSet = preparedStatement.executeQuery();

        while (resultSet.next())
        {
            final String versionName = resultSet.getString("value");
            log("Importing Version: " + versionName);

            final boolean created = createVersion(getProductName(resultSet, false), versionName);
            if (created)
            {
                count++;
            }
        }
        ImportUtils.closePS(preparedStatement);
        log(count + " versions imported from Bugzilla from the versions table.");
    }

    private void createVersionFromBugsTable(final Connection conn) throws SQLException
    {
        int count = 0;

        String sql;
        sql = "select product_id, target_milestone from bugs where " + whereSelectedProjectClauseForVersionsAndComponents() + " group by product_id, target_milestone";
        final PreparedStatement preparedStatement = conn.prepareStatement(sql);
        final ResultSet resultSet = preparedStatement.executeQuery();

        while (resultSet.next())
        {
            final String versionName = resultSet.getString("target_milestone");
            if (!"---".equals(versionName))
            {
                log("Importing Version: " + versionName);

                final String productName = getProductName(resultSet, true);
                final boolean created = createVersion(productName, versionName);
                if (created)
                {
                    count++;
                }
            }
        }
        log(count + " versions imported from Bugzilla from the bugs table.");
        ImportUtils.closePS(preparedStatement);
    }

    /**
     * Creates a clause for the where part of a query on Versions or Components
     * that restricts results to the correct projects. JRA-8555 seems to be due
     * to the crazy fact that old bugzilla versions use "program" in the
     * VERSIONS and COMPONENTS tables and "product" in the BUGS table.
     *
     * @return the clause suitable for putting after the where.
     */
    private String whereSelectedProjectClauseForVersionsAndComponents()
    {
        return " project_id in (" + commaSeparate(projectToBugzillaIdMap.values()) + ") ";
    }

    /**
     * Returns comma-separated text values of a list of objects.
     *
     * @param coll collection of objects to comma separate
     * @return comma separated list of Strings of objects from the given collection
     */
    public String commaSeparate(final Collection coll)
    {
        if (coll.size() == 0)
        {
            return "";
        }
        final StringBuffer buf = new StringBuffer();
        for (final Iterator it = coll.iterator(); it.hasNext();)
        {
            final Object o = it.next();
            buf.append(o);
            if (it.hasNext())
            {
                buf.append(",");
            }
        }
        return buf.toString();
    }

    private boolean createVersion(final String project, final String versionName)
    {
        final Version existingVersion = versionManager.getVersion(getProject(project), versionName);
        if (existingVersion != null)
        {
            log("Version: " + versionName + " in Project: " + project + " already exists. Not imported");
            versionKeys.put(project + ":" + versionName, existingVersion);
            return false;
        }
        else
        {
            Version version;
            try
            {
                version = versionManager.createVersion(versionName, null, null, getProject(project), null);
                versionKeys.put(project + ":" + versionName, version);
                return true;
            }
            catch (final Exception e)
            {
                log("Error importing Version: " + versionName);
                log(ExceptionUtils.getStackTrace(e));
                return false;
            }
        }
    }

	// DONE
	private void createProjects(final String[] projectNames, final Connection conn) throws SQLException
    {
        int count = 0;
        log("\n\nImporting project(s) " + selectedProjects);

        PreparedStatement preparedStatement;
        ResultSet resultSet;

        final String names = ImportUtils.getSQLTokens(projectNames);
        preparedStatement = conn.prepareStatement("Select * from trackers_project where project_name in (" + names + ") AND tracker_id = 3");

        for (int i = 0; i < projectNames.length; i++)
        {
            final String projectName = projectNames[i];
            preparedStatement.setString(i + 1, projectName);
        }

        resultSet = preparedStatement.executeQuery();
        while (resultSet.next())
        {
            final String product = resultSet.getString("project_name");
            projectToBugzillaIdMap.put(product, new Integer(resultSet.getInt("project_id")));

            log("Importing Project: " + product);

            final String description = resultSet.getString("project_description");
			final String productKey = resultSet.getString("project_name_unix");

            final boolean created = createProject(product, productKey, description);

            if (created)
            {
                count++;
            }
        }
        log(count + " projects imported from phpBB.");
        ImportUtils.closePS(preparedStatement);
    }

    private boolean createProject(final String product, final String productKey, final String description)
    {
        if (product == null)
        {
            throw new IllegalArgumentException("Product (description '" + description + "') cannot be null");
        }

        final GenericValue existingProject = projectManager.getProjectByName(product);
        if (existingProject != null)
        {
            log("Project: " + product + " already exists. Not imported");
            // JRA-11466 - MySQL is case-insensitive, so store product keys in lowercase
            projectKeys.put(product.toLowerCase(), existingProject);
            return false;
        }
        else
        {
            GenericValue project;
            try
            {
                project = ProjectUtils.createProject(EasyMap.build("key", productKey, "lead",
                    bugzillaMappingBean.getProjectLead(product), "name", product, "description", description));

                //Add the default permission scheme for this project
                permissionSchemeManager.addDefaultSchemeToProject(project);
                // Add the default issue type screen scheme for this project
                issueTypeScreenSchemeManager.associateWithDefaultScheme(project);
                // JRA-11466 - MySQL is case-insensitive, so store product keys in lowercase
                projectKeys.put(product.toLowerCase(), project);
                return true;
            }
            catch (final Exception e)
            {
                log("Error importing Project: " + product);
                log(ExceptionUtils.getStackTrace(e));
                return false;
            }
        }
    }

    private void createUser(final int bugzillaId) throws SQLException
    {
        profilePS.setInt(1, bugzillaId);
        final ResultSet resultSet = profilePS.executeQuery();

        final int count = createUserFrom(resultSet);
        if (count == 0)
        {
            throw new RuntimeException("Could not create bugzilla user " + bugzillaId + ", referenced in the bugzilla database.");
        }
        resultSet.close();
    }

    private int createUserFrom(final ResultSet resultSet) throws SQLException
    {
        int count = 0;
        String loginNameEmail;
        String fullname;
        while (resultSet.next())
        {
			// Username is our phpBB Username...
			loginNameEmail = getUsernameFromBugzillaProfile(resultSet);
            fullname = TextUtils.noNull(resultSet.getString("realname")).trim();

            final int user_id = resultSet.getInt("user_id");

            boolean created;
            if (cryptedPasswords)
            {
                //Newer versions of Bugzilla don't use the password field, but instead use
                //a hash.  We will ignore the passwords in this case
                created = createUser(loginNameEmail, fullname, user_id, null);

            }
            else
            {
                final String password = TextUtils.noNull(resultSet.getString("password")).trim();
                created = createUser(loginNameEmail, fullname, user_id, password);
            }
            if (created)
            {
                count++;
            }
        }
        return count;
    }

    /**
     * Given a Bugzilla 'profile' user record, infer a JIRA username from it.
     * In Bugzilla your username is your email address, and this will become your JIRA username, unless this method
     * is overridden to implement a different scheme.
     *
     * @param bugzillaProfileResultSet profile result set
     * @return username
     * @throws SQLException if reading from result set fails
     */
    protected String getUsernameFromBugzillaProfile(final ResultSet bugzillaProfileResultSet) throws SQLException
    {
//        return TextUtils.noNull(bugzillaProfileResultSet.getString("username")).toLowerCase().trim();
		return bugzillaProfileResultSet.getString("username");

        // Alternatively, use the first part ('joe' in 'joe@company.com')
        //        String name = bugzillaProfileResultSet.getString("username");
        //        name = TextUtils.noNull(name).trim();
        //        int i = name.indexOf("@");
        //        if (i != -1) name = name.substring(0, i);
        //        return name;
    }

    private boolean createUser(final String loginNameEmail, String fullname, final int bugzillaUserId, final String password)
    {
        log("Importing User: " + loginNameEmail);
        if (!TextUtils.stringSet(fullname))
        {
            fullname = getFullNameFromEmail(loginNameEmail);
        }
        try
        {
            final User user = UserUtils.getUser(loginNameEmail);
            if (user != null)
            {
                log("\tUser: " + loginNameEmail + " already exists. Not imported");
                userKeys.put(new Integer(bugzillaUserId), user);
                return reuseExistingUsers;
            }
        }
        catch (final EntityNotFoundException e)
        {
            try
            {
                // Bugzilla uses the email address as user id, whereas JIRA has a distinct string for this.
                // Here we check if the email address is currently owned by a user, to prevent a new user being
                // created if a logically identical one exists
                if (reuseExistingUsers)
                {
                    try
                    {
                        final User existingUser = UserUtils.getUserByEmail(loginNameEmail);
                        if (existingUser != null)
                        {
                            log("User with email '" + loginNameEmail + "' already exists (" + existingUser.getName() + "). Not imported");
                            userKeys.put(new Integer(bugzillaUserId), existingUser);
                            return reuseExistingUsers;
                        }
                    }
                    catch (final EntityNotFoundException ignored)
                    {
                        log4jLog.debug("Did not find user: " + loginNameEmail + " so a new user will be created");
                    }
                }

                // JRA-10393: if Jira is running with a user based license, the active user count will be
                // recalculated every time a user is created. Depending on how many users there are in the system
                // this may incur a performance penalty. If this becomes a problem in the future, we will need
                // to devise a way of creating multiple users without incrementally recalculating the active
                // user count.
                // Also, if the user is going to be created inactive, add an extra log message
                if (!userUtil.canActivateNumberOfUsers(1))
                {
                    log("User with email '" + loginNameEmail + "' will be created as an inactive user; user will not be able to log in to JIRA.");
                }

                User user = userUtil.createUserNoEvent(
                        loginNameEmail,
                        password,
                        loginNameEmail,
                        fullname);
                userKeys.put(new Integer(bugzillaUserId), user);
                return true;
            }
            catch (final Exception exception)
            {
                log("User: " + loginNameEmail + " not imported. An error occurred. " + exception.getMessage());
                return false;
            }
        }
        return false;
    }

    private void createAttachments(final Connection conn, final PreparedStatement attachPrepStatement, final int bug_id, final GenericValue issue) throws Exception
    {
        if (applicationProperties.getOption(APKeys.JIRA_OPTION_ALLOWATTACHMENTS))
        {
            ResultSet resultSet = null;
            try
            {
                attachPrepStatement.clearParameters();
                attachPrepStatement.setInt(1, bug_id);
                resultSet = attachPrepStatement.executeQuery();
                while (resultSet.next())
                {
                    String fileName = resultSet.getString("filename");
                    if (fileName.lastIndexOf('\\') > -1)
                    {
                        fileName = fileName.substring(fileName.lastIndexOf('\\') + 1);
                    }

                    if (fileName.lastIndexOf('/') > -1)
                    {
                        fileName = fileName.substring(fileName.lastIndexOf('/') + 1);
                    }

                    byte[] fileBytes;
                    try
                    {
                        fileBytes = resultSet.getBytes("thedata");
                    }
                    catch (final SQLException e)
                    {
                        final PreparedStatement ps = conn.prepareStatement("select thedata from attach_data where id = ?");
                        ps.setInt(1, resultSet.getInt("attach_id"));
                        final ResultSet attachmentRS = ps.executeQuery();
                        attachmentRS.next();
                        fileBytes = attachmentRS.getBytes("thedata");
                        attachmentRS.close();
                    }

                    final int submitterId = resultSet.getInt("submitter_id");
                    final Attachment attachment = attachmentManager.createAttachment(issue, getUser(submitterId), resultSet.getString("mimetype"),
                        fileName, new Long(fileBytes.length), null, UtilDateTime.nowTimestamp());
                    //we need to set the created date back to when it was created in the original system.
                    attachment.getGenericValue().set("created", resultSet.getTimestamp("creation_ts"));
                    attachment.store();

                    CoreFactory.getGenericDelegator().storeAll(EasyList.build(issue));
                    cacheManager.flush(CacheManager.ISSUE_CACHE, issue);

                    final File realAttachFile = AttachmentUtils.getAttachmentFile(attachment);
                    final BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(realAttachFile));
                    out.write(fileBytes, 0, fileBytes.length);
                    out.close();
                }
            }
            catch (final SQLException e)
            {
                log("Error on importing attachments for bug " + bug_id + ". Error:" + e.getMessage());
            }
            finally
            {
                if (resultSet != null) //prevent nullpointer - JRA-6154
                {
                    resultSet.close();
                }
            }
        }
        else
        {
            log("Attachments will not be imported from bugzilla since attachements are disabled in JIRA.");
        }
    }

    private void createLinks(final IssueLinkType linkType, final String inwardColumn, final String outwardColumn, final PreparedStatement linkInwardPrepStatement, final PreparedStatement linkOutwardPrepStatement, final int bug_id, final GenericValue issue) throws SQLException
    {
        final Long issueId = issue.getLong("id");
        ResultSet resultSet = null;
        try
        {
            linkInwardPrepStatement.clearParameters();
            linkInwardPrepStatement.setInt(1, bug_id);
            resultSet = linkInwardPrepStatement.executeQuery();
            while (resultSet.next())
            {
                final String inward = resultSet.getString(inwardColumn);
                final Long linkedIssueId = (Long) previouslyImportedKeys.get(new Integer(inward));
                if (linkedIssueId != null)
                {
                    try
                    {
                        final GenericValue linkedIssue = issueManager.getIssue(linkedIssueId);
                        if (linkedIssue == null)
                        {
                            log4jLog.error("Could not find issue with id " + linkedIssueId + " although it was once imported from bug #" + inward);
                            continue;
                        }
                        issueLinkManager.createIssueLink(linkedIssueId, issueId, linkType.getId(), null, null);
                        log("Creating link: issue " + issue.getString("key") + " " + linkType.getInward() + " " + linkedIssue.getString("key"));
                    }
                    catch (final CreateException e)
                    {
                        log4jLog.error(e, e);
                    }
                }
            }
            resultSet.close();

            linkOutwardPrepStatement.clearParameters();
            linkOutwardPrepStatement.setInt(1, bug_id);
            resultSet = linkOutwardPrepStatement.executeQuery();
            while (resultSet.next())
            {
                final String outward = resultSet.getString(outwardColumn);
                final Long linkedIssueId = (Long) previouslyImportedKeys.get(new Integer(outward));
                if (linkedIssueId != null)
                {
                    try
                    {
                        final GenericValue linkedIssue = issueManager.getIssue(linkedIssueId);
                        if (linkedIssue == null)
                        {
                            log4jLog.error("Could not find issue with id " + linkedIssueId + " although it was once imported from bug #" + outward);
                            continue;
                        }
                        issueLinkManager.createIssueLink(issueId, linkedIssueId, linkType.getId(), null, null);
                        log("Creating link: issue " + issue.getString("key") + " " + linkType.getOutward() + " " + linkedIssue.getString("key"));

                    }
                    catch (final CreateException e)
                    {
                        log4jLog.error(e, e);
                    }
                }
            }
        }
        catch (final SQLException e)
        {
            log("Error creating dependency link for bug " + bug_id + ". Error:" + e.getMessage());
        }
        finally
        {
            if (resultSet != null) //prevent nullpointer - JRA-6154
            {
                resultSet.close();
            }
        }
    }

    /**
     * Goes through imported issues and rewrites inline links (eg. 'bug #12345') to JIRA inline
     * links (JRA-XXXX).
     *
     * @throws GenericEntityException if database read or write fails
     */
    private void rewriteBugLinks() throws GenericEntityException
    {
        log("Rewriting bug links for " + importedKeys.size() + " issues.");

        final Iterator importedIssueIds = importedKeys.values().iterator();
        while (importedIssueIds.hasNext())
        {
            final Long issueId = (Long) importedIssueIds.next();
            final GenericValue issue = issueManager.getIssue(issueId);
            if (issue != null)
            {
                final String key = issue.getString("key");
                final String oldDescription = issue.getString("description");
                if ((oldDescription != null) && (oldDescription.length() > 0))
                {
                    final String newDescription = rewriteBugLinkInText(oldDescription, key);
                    if (!oldDescription.equals(newDescription))
                    {
                        issue.setString("description", newDescription);
                        issue.store();
                    }
                }

                final Collection comments = CoreFactory.getGenericDelegator().findByAnd("Action", EasyMap.build("type", "comment", "issue", issueId));
                final Iterator commentIter = comments.iterator();
                while (commentIter.hasNext())
                {
                    final GenericValue comment = (GenericValue) commentIter.next();
                    final String oldComment = comment.getString("body");
                    if ((oldComment != null) && (oldComment.length() > 0))
                    {
                        final String newComment = rewriteBugLinkInText(oldComment, key);
                        if (!oldComment.equals(newComment))
                        {
                            comment.setString("body", newComment);
                            comment.store();
                        }
                    }
                }
            }
        }
        cacheManager.flush(CacheManager.ISSUE_CACHE);
    }

    /**
     * Rewrite inline bug links ('bug #1234' etc) in a string.
     *
     * @param str            The text to rewrite
     * @param parentIssueKey Issue this text came from (purely for logging).
     * @return str, with links rewritten.
     */
    public String rewriteBugLinkInText(final String str, final String parentIssueKey)
    {
        Pattern pattern = null;
        try
        {
            pattern = new Perl5Compiler().compile("[bB]ug #?(\\d+)");
        }
        catch (final MalformedPatternException e)
        {
            log4jLog.error("Error parsing bug# regexp", e);
            return str;
        }
        return Util.substitute(new Perl5Matcher(), pattern, new Substitution()
        {
            public void appendSubstitution(final StringBuffer appendBuffer, final MatchResult match, final int substitutionCount, final PatternMatcherInput originalInput, final PatternMatcher matcher, final Pattern pattern)
            {
                final String bugId = match.group(1);
                final Long jiraIssueId = (Long) importedKeys.get(new Integer(bugId));
                if (jiraIssueId == null)
                {
                    log("No imported issue found for bug reference " + bugId + " in " + parentIssueKey);
                    appendBuffer.append(originalInput);
                }
                else
                {
                    final GenericValue issue = issueManager.getIssue(jiraIssueId);
                    log("In " + parentIssueKey + ": Rewriting '" + match.group(0) + "' to '" + issue.getString("key") + "'");
                    appendBuffer.append(issue.getString("key"));
                }
            }

        }, str, Util.SUBSTITUTE_ALL);
    }

    /**
     * Return an integer prefix of a string, if any.
     *
     * @param s String containing id
     * @return id
     */
    public Integer getIdFromStartOfString(final String s)
    {
        if ((s.length() == 0) || !Character.isDigit(s.charAt(0)))
        {
            return null;
        }

        final StringBuffer buf = new StringBuffer(5);
        for (int i = 0; i < Math.min(6, s.length()); i++)
        {
            final char c = s.charAt(i);
            if (Character.isDigit(c))
            {
                buf.append(c);
            }
            else if (Character.isLetter(c))
            {
                return null;
            }
            else
            {
                break;
            }
        }
        return new Integer(Integer.parseInt(buf.toString()));
    }

    private GenericValue getProject(final String project)
    {
        if (project == null)
        {
            throw new IllegalArgumentException("Can not resolve a project specified by null.");
        }
        return (GenericValue) projectKeys.get(project.toLowerCase());
    }

    private Version getVersion(final String value)
    {
        return (Version) versionKeys.get(value);
    }

    private GenericValue getComponent(final String value)
    {
        return (GenericValue) componentKeys.get(value);
    }

    private User getUser(final int bugzillaUserId) throws SQLException
    {
        final Integer idInt = new Integer(bugzillaUserId);
        User user = (User) userKeys.get(idInt);
        if (user == null)
        {
            createUser(bugzillaUserId);
            user = (User) userKeys.get(idInt);
        }
        return user;
    }

    private String generatePaddingString(final int length)
    {
        final char[] padarray = new char[length];
        for (int i = 0; i < length; i++)
        {
            padarray[i] = 'J';
        }
        return String.valueOf(padarray);
    }

    public String getFullNameFromEmail(final String email)
    {
        if (email == null)
        {
            return "";
        }

        final int index = email.indexOf("@");
        if (index != -1)
        {
            return email.substring(0, index);
        }
        else
        {
            return "";
        }
    }

    private void log(final String s)
    {
        importLog.append("[").append(new SimpleDateFormat("HH:mm:ss").format(new Date())).append("] ");
        importLog.append(s);
        importLog.append("\n");
        log4jLog.info(s);
    }

    private static Object getOnly(final Collection singleCol)
    {
        if (singleCol == null)
        {
            return null;
        }
        else if (singleCol.size() > 1)
        {
            throw new IllegalArgumentException("Passes Collection with more than one element");
        }
        else if (singleCol.isEmpty())
        {
            throw new IllegalArgumentException("Passed Collection with no elements");
        }
        else
        {
            return singleCol.iterator().next();
        }
    }

    public String getImportLog()
    {
        return importLog.toString();
    }

	// DONE
    public static List getAllBugzillaProjects(BugzillaConnectionBean connectionBean) throws java.sql.SQLException
    {
        PreparedStatement preparedStatement = null;
        try
        {
            preparedStatement = connectionBean.getConnection().prepareStatement("Select project_name from trackers_project where tracker_id = 3 order by project_name");
            ResultSet resultSet = preparedStatement.executeQuery();
            List projects = new ArrayList();
            while (resultSet.next())
            {
				// Solved initial bug in Bugzilla importer - column_name wrong
                String product = resultSet.getString("project_name");
                projects.add(product);
            }
            return projects;
        }
        finally
        {
            try
            {
                if (preparedStatement != null)
                {
                    preparedStatement.close();
                }
            }
            finally
            {
                connectionBean.closeConnection();
            }
        }
    }

    private void createOrFindCustomFields() throws GenericEntityException
    {
        final CustomFieldType numericFieldCFType = customFieldManager.getCustomFieldType(CreateCustomField.FIELD_TYPE_PREFIX + BUGZILLA_ID_TYPE);
        final CustomFieldSearcher numericSearcher = customFieldManager.getCustomFieldSearcher(CreateCustomField.FIELD_TYPE_PREFIX + BUGZILLA_ID_SEARCHER);

        if (numericFieldCFType != null)
        {
            bugzillaIdCustomField = customFieldManager.getCustomFieldObjectByName(BUGZILLA_ID_CF_NAME);
            if (bugzillaIdCustomField == null)
            {
                bugzillaIdCustomField = customFieldManager.createCustomField(BUGZILLA_ID_CF_NAME, BUGZILLA_ID_CF_NAME, numericFieldCFType,
                    numericSearcher, EasyList.build(GlobalIssueContext.getInstance()), EasyList.buildNull());
                externalUtils.associateCustomFieldWithScreen(bugzillaIdCustomField, null);
            }
        }
        else
        {
            log("WARNING: FieldType '" + BUGZILLA_ID_TYPE + "' is required for Bugzilla Ids but has not been configured. ID fields will not be created");
        }

    }

    /**
     * Returns a stored IssueLinkType with the specified name, or creates and returns a new
     * IssueLinkType using the supplied parameters
     *
     * @param name    The name of the IssueLinkType e.g. "Duplicate"
     * @param outward The outward link description "duplicates"
     * @param inward  The inward link description "is duplicated by"
     * @return issueLinkType
     */
    private IssueLinkType createOrFindLinkType(final String name, final String outward, final String inward)
    {
        IssueLinkType linkType = getLinkType(name);
        if (linkType == null)
        {
            issueLinkTypeManager.createIssueLinkType(name, outward, inward, null);
            linkType = getLinkType(name);
        }
        return linkType;
    }

    /**
     * Returns a stored IssueLinkType with the specified name, or null if none exist
     *
     * @param name The name of the IssueLinkType e.g. "Duplicate"
     * @return issueLinkType
     */
    private IssueLinkType getLinkType(final String name)
    {
        final Collection linkTypes = issueLinkTypeManager.getIssueLinkTypesByName(name);

        if (linkTypes.size() > 0)
        {
            return (IssueLinkType) linkTypes.iterator().next();
        }
        else
        {
            return null;
        }
    }

    private Set getAssociatedUsers(final BugzillaConnectionBean connectionBean, final String[] projectNames)
    {
        try
        {
            final Connection connection = connectionBean.getConnection();
            final UserNameCollator collator = new UserNameCollator(projectNames, connection);
            return collator.getAllUsers();
        }
        catch (final SQLException e)
        {
            throw new DataAccessException(e);
        }
    }

    private static boolean tableHasColumn(final Connection conn, final String table, final String column) throws SQLException
    {
        final ResultSet rs = conn.getMetaData().getColumns(null, null, table, column);
        final boolean next = rs.next();
        rs.close();
        return next;
    }

    private static interface BugzillaMappingBean
    {
        /**
         * The JIRA issue type to use for Bugzilla bugs that are 'enhancements'.
         */
        String JIRA_ENHANCEMENT_ISSUE_TYPE_ID = "4";
        /**
         * The JIRA issue type to use for normal Bugzilla bugs.
         */
        String JIRA_BUG_ISSUE_TYPE_ID = "1";

        public String getPriority(String originalPriority);

        public String getResolution(String originalResolution);

        public String getStatus(String originalStatus);

        public Integer getWorkflowStep(String originalWorkflowStep);

        public String getWorkflowStatus(String originalWorkflowStatus);

        public String getProjectLead(String project);
    }

    public static abstract class DefaultBugzillaMappingBean implements BugzillaMappingBean
    {
        private static Map priorityMap = new HashMap();
        private static Map resolutionMap = new HashMap();
        private static Map statusMap = new HashMap();
        private static Map wfStepMap = new HashMap();
        private static Map wfStatusMap = new HashMap();

        static
        {
            // bugzilla's severities mapping to JIRA priorities
            priorityMap.put("blocker", "" + IssueFieldConstants.BLOCKER_PRIORITY_ID);
            priorityMap.put("critical", "" + IssueFieldConstants.CRITICAL_PRIORITY_ID);
            priorityMap.put("major", "" + IssueFieldConstants.MAJOR_PRIORITY_ID);
            priorityMap.put("normal", "" + IssueFieldConstants.MAJOR_PRIORITY_ID);
            priorityMap.put("enhancement", "" + IssueFieldConstants.MINOR_PRIORITY_ID);
            priorityMap.put("minor", "" + IssueFieldConstants.MINOR_PRIORITY_ID);
            priorityMap.put("trivial", "" + IssueFieldConstants.TRIVIAL_PRIORITY_ID);

            // bugzilla resolutions mapping to JIRA resolutions
            resolutionMap.put("", null);
            resolutionMap.put("FIXED", "" + IssueFieldConstants.FIXED_RESOLUTION_ID);
            resolutionMap.put("INVALID", "" + IssueFieldConstants.INCOMPLETE_RESOLUTION_ID);
            resolutionMap.put("WONTFIX", "" + IssueFieldConstants.WONTFIX_RESOLUTION_ID);
            resolutionMap.put("LATER", "" + IssueFieldConstants.WONTFIX_RESOLUTION_ID);
            resolutionMap.put("REMIND", "" + IssueFieldConstants.WONTFIX_RESOLUTION_ID);
            resolutionMap.put("DUPLICATE", "" + IssueFieldConstants.DUPLICATE_RESOLUTION_ID);
            resolutionMap.put("WORKSFORME", "" + IssueFieldConstants.CANNOTREPRODUCE_RESOLUTION_ID);
            resolutionMap.put("NEEDTESTCASE", "" + IssueFieldConstants.INCOMPLETE_RESOLUTION_ID);

            // bugzilla status mapping to JIRA status
            statusMap.put("UNCONFIRMED", "" + IssueFieldConstants.OPEN_STATUS_ID);
            statusMap.put("NEW", "" + IssueFieldConstants.OPEN_STATUS_ID);
            statusMap.put("ASSIGNED", "" + IssueFieldConstants.OPEN_STATUS_ID);
            statusMap.put("REOPENED", "" + IssueFieldConstants.REOPENED_STATUS_ID);
            statusMap.put("RESOLVED", "" + IssueFieldConstants.RESOLVED_STATUS_ID);
            statusMap.put("VERIFIED", "" + IssueFieldConstants.RESOLVED_STATUS_ID);
            statusMap.put("CLOSED", "" + IssueFieldConstants.CLOSED_STATUS_ID);

            // workflow Mappings
            wfStepMap.put("1", new Integer("1"));
            wfStepMap.put("2", new Integer("2"));
            wfStepMap.put("3", new Integer("3"));
            wfStepMap.put("4", new Integer("5"));
            wfStepMap.put("5", new Integer("4"));
            wfStepMap.put("6", new Integer("6"));

            wfStatusMap.put("1", "Open");
            wfStatusMap.put("3", "In Progress");
            wfStatusMap.put("4", "Reopened");
            wfStatusMap.put("5", "Resolved");
            wfStatusMap.put("6", "Closed");
        }

        public String getPriority(final String originalPriority)
        {
            return (String) priorityMap.get(originalPriority);
        }

        public String getResolution(final String originalResolution)
        {
            return (String) resolutionMap.get(originalResolution);
        }

        public String getStatus(final String originalStatus)
        {
            return (String) statusMap.get(originalStatus);
        }

        public Integer getWorkflowStep(final String originalWorkflowStep)
        {
            return (Integer) wfStepMap.get(originalWorkflowStep);
        }

        public String getWorkflowStatus(final String originalWorkflowStatus)
        {
            return (String) wfStatusMap.get(originalWorkflowStatus);
        }
    }

/**
* responsible for getting a Set of user names
*/
private class UserNameCollator
{
	private final String projectIds;
	private final Connection conn;

	// DONE
	UserNameCollator(final String[] projectNames, final Connection conn) throws SQLException
	{
		this.conn = conn;
		PreparedStatement preparedStatement = null;
		ResultSet rs = null;
		try
		{
			preparedStatement = conn.prepareStatement("Select project_id from trackers_project where project_name in (" + ImportUtils.getSQLTokens(projectNames) + ") AND tracker_id = 3");
			for (int i = 0; i < projectNames.length; i++)
			{
				final String projectName = projectNames[i];
				preparedStatement.setString(i + 1, projectName);
			}

			rs = preparedStatement.executeQuery();
			final StringBuffer buffer = new StringBuffer();
			int i = 0;
			while (rs.next())
			{
				if (i++ > 0)
				{
					buffer.append(", ");
				}
				buffer.append(rs.getLong(1));
			}
			projectIds = buffer.toString();
		}
		finally
		{
			ImportUtils.close(preparedStatement, rs);
		}
	} // end ctor

	// DONE
	public Set getAllUsers() throws SQLException
	{
		final Set result = new HashSet();

		/*issue reporters
		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN bugs AS b ON ( b.reporter = prof.userid) JOIN products AS p ON (b.product_id = p.id) WHERE p.id IN (" + projectIds + ") GROUP BY 1"));

		// issue assignees
		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN bugs AS b ON ( b.assigned_to = prof.userid) JOIN products AS p ON (b.product_id = p.id) WHERE p.id IN (" + projectIds + ") GROUP BY 1"));

		// commenters
		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN longdescs AS l ON ( l.who = prof.userid) JOIN bugs AS b ON (l.bug_id = b.bug_id) JOIN products AS p ON(b.product_id = p.id) WHERE p. id IN (" + projectIds + ") GROUP BY 1"));

		// voters
//		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN votes AS v ON ( v.who = prof.userid) JOIN bugs AS b ON (v.bug_id = b.bug_id) JOIN products AS p ON(b.product_id = p.id) WHERE p. id IN (" + projectIds + ") GROUP BY 1"));

		// watchers
		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN cc AS c ON ( c.who = prof.userid) JOIN bugs AS b ON (c.bug_id = b.bug_id) JOIN products AS p ON(b.product_id = p.id) WHERE p. id IN (" + projectIds + ") GROUP BY 1"));

		// attachers
		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN attachments AS a ON ( a.submitter_id = prof.userid) JOIN bugs AS b ON (a.bug_id = b.bug_id) JOIN products AS p ON(b.product_id = p.id) WHERE p. id IN (" + projectIds + ") GROUP BY 1"));

		// workers
		result.addAll(getUsers("SELECT prof.login_name, prof.realname FROM profiles AS prof JOIN bugs_activity AS ba ON ( ba.who = prof.userid) JOIN bugs AS b ON (ba.bug_id = b.bug_id) JOIN products AS p ON(b.product_id = p.id) WHERE ba.fieldid = 45 AND p.id IN (" + projectIds + ") GROUP BY 1"));
*/

		// Ticket History
		result.addAll(getUsers("SELECT u.username, u.username as realname FROM community_users AS u JOIN trackers_history AS h ON (h.user_id = u.user_id) JOIN trackers_ticket as t ON (h.ticket_id = t.ticket_id) WHERE t.project_id IN (" + projectIds + ") GROUP BY 1"));

		// Trackers Posts
		result.addAll(getUsers("SELECT u.username, u.username as realname FROM community_users AS u JOIN trackers_post AS p ON (p.user_id = u.user_id) JOIN trackers_ticket as t ON (p.ticket_id = t.ticket_id) WHERE t.project_id IN (" + projectIds + ") GROUP BY 1"));

		// Watchers/Project
		result.addAll(getUsers("SELECT u.username, u.username as realname FROM community_users AS u JOIN trackers_project_watch AS pw ON (pw.user_id = u.user_id) WHERE pw.project_id IN (" + projectIds + ") GROUP BY 1"));

		// Watchers/Ticket
		result.addAll(getUsers("SELECT u.username, u.username as realname FROM community_users AS u JOIN trackers_ticket_watch AS tw ON (tw.user_id = u.user_id) JOIN trackers_ticket as t ON (tw.ticket_id = t.ticket_id) WHERE t.project_id IN (" + projectIds + ") GROUP BY 1"));
		
		// ticket reporters
		result.addAll(getUsers("SELECT u.username, u.username as realname FROM community_users AS u JOIN trackers_ticket AS t ON (t.user_id = u.user_id) WHERE t.project_id IN (" + projectIds + ") GROUP BY 1"));

		// Ticket assignees
		result.addAll(getUsers("SELECT u.username, u.username as realname FROM community_users AS u JOIN trackers_ticket AS t ON (t.assigned_user = u.user_id) WHERE t.project_id IN (" + projectIds + ") GROUP BY 1"));


		return result;
	}

	private Set getUsers(final String sql) throws SQLException
	{
		PreparedStatement ps = null;
		ResultSet rs = null;
		try
		{
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			final Set result = new HashSet();
			while (rs.next())
			{
				result.add(new ExternalUser(rs.getString(1), rs.getString(2), rs.getString(1)));
			}
			return result;
		}
		finally
		{
			ImportUtils.close(ps, rs);
		}
	}
}

/**
 * Returns an unmodifiable set of issue keys that have summaries longer that acceptable by JIRA
 *
 * @return an unmodifiable set of issue keys as Strings
 */
public Set /* <String> */getTruncSummaryIssueKeys()
{
	return Collections.unmodifiableSet(truncSummaryIssueKeys);
}
}
