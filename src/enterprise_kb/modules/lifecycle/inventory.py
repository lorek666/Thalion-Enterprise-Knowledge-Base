LOCAL_INVENTORY = """
WITH target AS MATERIALIZED (
    SELECT version.org_id, version.space_id, version.version_id, version.asset_id,
           jsonb_build_array(organization.safety_epoch, space.safety_epoch, source.safety_epoch, source.lifecycle) AS safety,
           (statement_timestamp() AT TIME ZONE organization.business_timezone)::date AS business_day,
           (version.registered_at AT TIME ZONE organization.business_timezone)::date AS registered_day
    FROM thalion.document_version AS version
    JOIN thalion.organization AS organization USING (org_id)
    JOIN thalion.space AS space USING (org_id, space_id)
    JOIN thalion.source AS source USING (org_id, space_id, source_id)
    WHERE (version.org_id, version.space_id, version.version_id) = (%(org)s, %(space)s, %(version)s)
), manifests AS MATERIALIZED (
    SELECT related.org_id, related.space_id, related.manifest_ref
    FROM target JOIN thalion.lifecycle_version_manifest AS related USING (org_id, space_id, version_id)
    LIMIT %(copy_bound)s
), derived AS MATERIALIZED (
    SELECT revision.org_id, revision.space_id, revision.revision_ref, revision.manifest_ref
    FROM manifests JOIN thalion.wiki_revision AS revision USING (org_id, space_id, manifest_ref)
    LIMIT %(copy_bound)s
), publications AS MATERIALIZED (
    SELECT publication.org_id, publication.space_id, publication.revision_ref, publication.publication_ref
    FROM derived JOIN thalion.wiki_publication_event AS publication USING (org_id, space_id, revision_ref)
), archive_requests AS MATERIALIZED (
    SELECT request.org_id, request.space_id, request.export_ref
    FROM target JOIN thalion.synthetic_export_request AS request USING (org_id, space_id, version_id)
    UNION
    SELECT request.org_id, request.space_id, request.export_ref
    FROM publications JOIN thalion.synthetic_export_request AS request
      ON (request.org_id, request.space_id, request.wiki_publication_ref) =
         (publications.org_id, publications.space_id, publications.publication_ref)
), copies AS MATERIALIZED (
    SELECT 'original' AS kind, jsonb_build_array(asset_id) AS identity FROM target
    UNION ALL
    SELECT 'backup', jsonb_build_array(backup.backup_ref, backup.asset_id, encode(backup.content_digest, 'hex'),
                                      backup.byte_length, encode(backup.store_identity, 'hex'))
    FROM target JOIN thalion.synthetic_backup_copy AS backup USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'export', jsonb_build_array(package.package_ref, encode(package.archive_digest, 'hex'))
    FROM archive_requests JOIN thalion.synthetic_export_package AS package USING (org_id, space_id, export_ref)
    UNION ALL
    SELECT 'processing_manifest', jsonb_build_array(run.run_ref)
    FROM target JOIN thalion.processing_run AS run USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'index', jsonb_build_array(projection.index_ref, projection.run_ref, projection.profile,
                                      encode(projection.content_digest, 'hex'))
    FROM target JOIN thalion.synthetic_lexical_index AS projection USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'index', jsonb_build_array('vector', vindex.index_ref, vindex.run_ref, vindex.model_id,
                                      vindex.generation, encode(vindex.content_digest, 'hex'))
    FROM target JOIN thalion.synthetic_vector_index AS vindex USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'transcription', jsonb_build_array(excerpt.passage_id, excerpt.excerpt_revision, excerpt.run_ref)
    FROM target JOIN thalion.passage_excerpt AS excerpt USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'wiki_input_manifest', jsonb_build_array(manifest_ref) FROM manifests
    UNION ALL
    SELECT 'wiki_revision', jsonb_build_array(revision_ref, manifest_ref) FROM derived
    LIMIT %(copy_bound)s
), facts AS MATERIALIZED (
    SELECT 'rule_interval' AS kind, NULL::uuid AS copy_ref,
           jsonb_build_array(rule.decision_ref, rule.effective_to,
               daterange(rule.valid_from, rule.effective_to, '[)') @> target.business_day) AS evidence
    FROM target JOIN thalion.rule_interval AS rule USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'rule_stop', NULL, jsonb_build_array(stop.decision_ref, stop.kind)
    FROM target JOIN thalion.rule_use_stop AS stop USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'hold', NULL, jsonb_build_array(hold.generation, hold.action)
    FROM target JOIN thalion.current_version_hold AS hold USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'backup_expiry', plan.backup_ref, jsonb_build_array(plan.schedule_ref,
           to_char(plan.expected_expiry_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           statement_timestamp() >= plan.expected_expiry_at, observation.observation_ref,
           to_char(observation.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM target JOIN thalion.synthetic_backup_expiry_plan AS plan USING (org_id, space_id, version_id)
    LEFT JOIN thalion.synthetic_backup_expiry_observation AS observation USING (org_id, space_id, backup_ref, schedule_ref)
    UNION ALL
    SELECT 'quality', quality.run_ref, jsonb_build_array(quality.decision_ref, quality.outcome)
    FROM target JOIN thalion.quality_decision AS quality USING (org_id, space_id, version_id)
    UNION ALL
    SELECT 'pending_processing', NULL, jsonb_build_array(job.job_id, job.generation, job.state)
    FROM target JOIN thalion.job AS job USING (org_id, space_id)
    WHERE job.target_ref = %(ref)s AND job.stage = 'parse' AND job.state <> 'succeeded'
    UNION ALL
    SELECT 'wiki_base_input', manifests.manifest_ref, jsonb_build_array(child.manifest_ref)
    FROM manifests JOIN thalion.input_manifest AS child
      ON (child.org_id, child.space_id) = (manifests.org_id, manifests.space_id)
     AND child.parent_refs @> ARRAY[manifests.manifest_ref]
    UNION ALL
    SELECT 'wiki_review', derived.revision_ref, jsonb_build_array('material', material.check_id)
    FROM derived JOIN thalion.wiki_review_material AS material USING (org_id, space_id, revision_ref)
    UNION ALL
    SELECT 'wiki_review', derived.revision_ref, jsonb_build_array('decision', review.review_ref)
    FROM derived JOIN thalion.wiki_review AS review USING (org_id, space_id, revision_ref)
    UNION ALL
    SELECT 'wiki_publication', revision_ref, jsonb_build_array(publication_ref) FROM publications
    UNION ALL
    SELECT 'wiki_availability', publications.revision_ref, jsonb_build_array(event.event_ref)
    FROM publications JOIN thalion.wiki_availability_event AS event USING (org_id, space_id, publication_ref)
    UNION ALL
    SELECT 'conflict_evidence', derived.revision_ref, jsonb_build_array(finding.finding_ref)
    FROM derived JOIN thalion.lint_finding_revision AS finding USING (org_id, space_id, revision_ref)
    LIMIT %(fact_bound)s
)
SELECT target.safety, policy.revision, policy.action, policy.keep_days, target.business_day - target.registered_day,
       coalesce((SELECT jsonb_agg(jsonb_build_array(kind, identity) ORDER BY kind, identity) FROM copies), '[]'::jsonb),
       coalesce((SELECT jsonb_agg(jsonb_build_array(kind, copy_ref, evidence) ORDER BY kind, copy_ref, evidence)
                 FROM facts), '[]'::jsonb)
FROM target LEFT JOIN LATERAL (
    SELECT revision, action, keep_days, contract_revision FROM thalion.retention_policy_revision
    WHERE (org_id, space_id, source_id) = (target.org_id, target.space_id, %(source)s)
    ORDER BY revision DESC LIMIT 1
) AS policy ON policy.contract_revision = %(contract)s
"""
