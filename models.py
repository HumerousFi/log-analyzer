from pydantic import BaseModel


class GroupedIssue(BaseModel):
    issue_type: str
    count: int


class LogAnalysisResponse(BaseModel):
    total_errors: int
    total_warnings: int
    timestamps: list[str]
    grouped_issues: list[GroupedIssue]
    most_frequent_issues: list[GroupedIssue]
    severity_breakdown: list[GroupedIssue]
    suspicious_activity: list[GroupedIssue]
    top_problem_lines: list[dict]
    summary: dict