using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JWTAuthDotNetIdentity.Migrations
{
    /// <inheritdoc />
    public partial class AddingRemoveAccountTokensTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Discriminator",
                table: "ResetPasswordTokens",
                type: "nvarchar(21)",
                maxLength: 21,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Discriminator",
                table: "ResetPasswordTokens");
        }
    }
}
